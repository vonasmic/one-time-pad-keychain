package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeManage;
import fel.cvut.tls.SoftwareLeaf;
import fel.cvut.usb.SeUsbLink;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Scanner;
import java.util.function.Function;

/**
 * Chip enrollment as one sequence. LAB signs the on-chip ML-DSA CSR with the
 * local client CA, installs via INSERT SIGNED CSR, and never pairs. PROD writes
 * the CSR only (no install); the operator runs INSERT SIGNED CSR after an
 * external CA signs. PROD may burn factory SH0 over MANAGE and write
 * pairing-key.hex for PAIRING LOAD after a reflash. USB is
 * {@link ChipPort}; cert files are {@link Certs}.
 */
final class ChipInit {

    enum Profile {
        LAB {
            @Override
            boolean replaceOccupiedEcc() {
                return false;
            }

            @Override
            boolean signLocally() {
                return true;
            }

            @Override
            boolean allowPairing() {
                return false;
            }
        },
        PROD {
            @Override
            boolean replaceOccupiedEcc() {
                return true;
            }

            @Override
            boolean signLocally() {
                return false;
            }

            @Override
            boolean allowPairing() {
                return true;
            }
        };

        abstract boolean replaceOccupiedEcc();

        abstract boolean signLocally();

        abstract boolean allowPairing();
    }

    sealed interface OwnerSetResult {
        record AlreadyEnrolled() implements OwnerSetResult {
        }

        record Ok() implements OwnerSetResult {
        }

        record Failed(String detail) implements OwnerSetResult {
        }
    }

    interface ChipPort {
        OwnerSetResult ownerSet(byte[] password, byte[] spki, byte[] saeCa) throws Exception;

        Optional<byte[]> tropicPub() throws Exception;

        /** Present when KEM INIT has already stored the ML-KEM public key (slot 510). */
        Optional<byte[]> tropicKemPub() throws Exception;

        SeManage.Reply manage(int cmd, String pin, byte[] body) throws Exception;

        byte[] clientCsrPub() throws Exception;

        /** Present when device cert + Tropic ECC exist ({@code CLIENT HASH}). */
        Optional<byte[]> clientHash() throws Exception;
    }

    interface Certs {
        byte[] signLab(Path clientCaP12, String clientCaP12Password, byte[] csrPub, String deviceCn)
                throws Exception;

        void writePem(byte[] certDer, Path path) throws Exception;

        Optional<byte[]> loadDerIfPresent(Path path) throws Exception;

        void writeCsrHex(Path path, byte[] pub) throws IOException;

        void writePairingKeyHex(Path path, int slot, byte[] priv, byte[] pub) throws IOException;

        boolean isRegularFile(Path path);
    }

    record EnrollRequest(
            byte[] resetPassword,
            String pin,
            Optional<Integer> pairingSlot,
            Path deviceCert,
            Path clientCaP12,
            String clientCaP12Password,
            String deviceCn,
            byte[] ownerSpki,
            byte[] saeCaDer
    ) {
        EnrollRequest {
            Objects.requireNonNull(resetPassword, "resetPassword");
            Objects.requireNonNull(pin, "pin");
            Objects.requireNonNull(pairingSlot, "pairingSlot");
            Objects.requireNonNull(deviceCert, "deviceCert");
            Objects.requireNonNull(deviceCn, "deviceCn");
            Objects.requireNonNull(ownerSpki, "ownerSpki");
            Objects.requireNonNull(saeCaDer, "saeCaDer");
        }
    }

    record EnrollResult(boolean ok, String stoppedAt, String message) {
        static EnrollResult ok(String message) {
            return new EnrollResult(true, null, message);
        }

        static EnrollResult stop(String at, String message) {
            return new EnrollResult(false, at, message);
        }
    }

    static final Certs FILE_CERTS = new FileCerts();

    static final String MSG_KEM_ALREADY_PROVISIONED =
            "ML-KEM is already provisioned (slot 510 / TROPIC KEM PUB). "
                    + "INIT cannot change the Tropic PIN or re-run KEM INIT. "
                    + "Use REPLACE to change the owner password (device renew); "
                    + "use MANAGE KEYGEN, PEER, and INSERT SIGNED CSR for other enrollment changes.";

    static final String OWNER_PASSWORD_PROMPT =
            "Owner password for device renew (not attempt-locked — use a strong password; 8-64 printable ASCII): ";
    static final String NEW_OWNER_PASSWORD_PROMPT =
            "New owner password for device renew (not attempt-locked — use a strong password; 8-64 printable ASCII): ";
    static final String OWNER_PASSWORD_CONFIRM_PROMPT = "Confirm owner password: ";
    static final String TROPIC_PIN_PROMPT =
            "Tropic PIN for encrypt/decrypt (8 attempts max; 8-16 printable ASCII): ";
    static final String TROPIC_PIN_CONFIRM_PROMPT = "Confirm Tropic PIN: ";

    private ChipInit() {
    }

    static void run(Scanner sc, SeUsbLink usb, Function<Scanner, String> readPin,
                    SSLContext ctx, Path deviceCert, Path saeCa, Path clientCaP12,
                    String clientCaP12Password, String deviceCn, byte[] ownerSpki, Profile profile)
            throws Exception {
        printWizard(profile);

        OwnerAuth chip = new OwnerAuth(usb, ctx);
        EnrollResult preflight = refuseIfKemProvisioned(chip);
        if (!preflight.ok()) {
            System.err.println("INIT refused: " + preflight.message());
            return;
        }

        String resetPw = readOwnerPassword(sc);
        if (resetPw == null) {
            return;
        }
        String pin = readConfirmedPin(sc, readPin);
        if (pin == null) {
            return;
        }
        Optional<Integer> slot = Optional.empty();
        if (profile.allowPairing()) {
            slot = readPairingSlot(sc);
            if (slot == null) {
                return;
            }
        }

        System.out.print("Type YES to continue (anything else cancels): ");
        if (!sc.hasNextLine()) {
            return;
        }
        if (!"YES".equals(sc.nextLine().trim())) {
            System.err.println("INIT cancelled.");
            return;
        }

        EnrollResult result = enroll(
                chip,
                FILE_CERTS,
                profile,
                new EnrollRequest(
                        resetPw.getBytes(StandardCharsets.US_ASCII),
                        pin,
                        slot,
                        deviceCert,
                        clientCaP12,
                        clientCaP12Password,
                        deviceCn,
                        ownerSpki,
                        derCert(saeCa)));
        if (!result.ok()) {
            System.err.println("INIT stopped at " + result.stoppedAt() + ": " + result.message());
        } else if (result.message() != null && !result.message().isBlank()) {
            System.out.println(result.message());
        }
    }

    /**
     * Typed LAB/PROD pipeline. USB text stays behind {@link ChipPort}.
     */
    static EnrollResult enroll(ChipPort chip, Certs certs, Profile profile, EnrollRequest req)
            throws Exception {
        Objects.requireNonNull(chip, "chip");
        Objects.requireNonNull(certs, "certs");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(req, "req");

        EnrollResult preflight = refuseIfKemProvisioned(chip);
        if (!preflight.ok()) {
            return preflight;
        }

        switch (chip.ownerSet(req.resetPassword(), req.ownerSpki(), req.saeCaDer())) {
            case OwnerSetResult.Failed failed -> {
                return EnrollResult.stop("OWNER SET", failed.detail());
            }
            case OwnerSetResult.AlreadyEnrolled ignored -> {
                System.out.println("OWNER SET: already enrolled");
            }
            case OwnerSetResult.Ok ignored -> {
                System.out.println("OWNER SET ok");
            }
        }

        Optional<byte[]> eccPub = chip.tropicPub();
        if (eccPub.isPresent()) {
            if (profile.replaceOccupiedEcc()) {
                SeManage.Reply replaced = chip.manage(SeManage.CMD_KEYGEN, null, null);
                if (!replaced.ok()) {
                    return EnrollResult.stop("KEYGEN", replaced.describe());
                }
                System.out.println(replaced.describe());
            } else {
                System.out.println("KEYGEN skipped (ECC occupied)");
            }
        } else {
            SeManage.Reply generated = chip.manage(SeManage.CMD_KEYGEN, null, null);
            if (!generated.ok()) {
                return EnrollResult.stop("KEYGEN", generated.describe());
            }
            System.out.println(generated.describe());
        }

        SeManage.Reply kem = chip.manage(SeManage.CMD_KEM_INIT, req.pin(), null);
        if (!kem.ok()) {
            return EnrollResult.stop("KEM INIT", kem.describe());
        }
        System.out.println(kem.describe());

        byte[] csrPub;
        try {
            csrPub = exportClientCsr(chip, certs, req.deviceCert());
        } catch (IOException e) {
            return EnrollResult.stop("CLIENT CSR", e.getMessage());
        }

        if (profile.signLocally()) {
            if (req.clientCaP12() == null || !certs.isRegularFile(req.clientCaP12())) {
                return EnrollResult.stop("INSERT SIGNED CSR", "INIT LAB needs the local client CA PKCS#12 at "
                        + req.clientCaP12());
            }
            if (req.clientCaP12Password() == null || req.clientCaP12Password().isEmpty()) {
                return EnrollResult.stop("INSERT SIGNED CSR",
                        "INIT LAB needs the client CA PKCS#12 password "
                                + "(set USERAPP_CLIENT_CA_P12_PASSWORD at startup)");
            }
            byte[] issued = certs.signLab(
                    req.clientCaP12(), req.clientCaP12Password(), csrPub, req.deviceCn());
            certs.writePem(issued, req.deviceCert());
            EnrollResult installed = insertSignedCsr(chip, issued);
            if (!installed.ok()) {
                return installed;
            }
        } else {
            System.out.println("INIT PROD: CSR written; run INSERT SIGNED CSR after the authority signs it.");
        }

        if (!profile.allowPairing() || req.pairingSlot().isEmpty()) {
            return finishWithClientHash(chip,
                    "INIT " + profile + " finished (pairing unchanged; factory SH0 not burned).");
        }

        SeManage.Reply pairing = chip.manage(
                SeManage.CMD_PAIRING, null,
                SeManage.encodePairingBody(req.pairingSlot().orElseThrow()));
        if (!pairing.ok()) {
            return EnrollResult.stop("PAIRING", pairing.describe());
        }
        SeManage.PairingKey key;
        try {
            key = SeManage.parsePairingOkMsg(pairing.msg());
        } catch (IllegalArgumentException e) {
            return EnrollResult.stop("PAIRING", "pairing private key was not in the reply");
        }
        Path pairingPath = pairingKeyPath(req.deviceCert());
        certs.writePairingKeyHex(pairingPath, key.slot(), key.priv(), key.pub());
        System.out.println("PAIRING ok (key saved to " + pairingPath + ")");
        return finishWithClientHash(chip,
                "INIT PROD finished (pairing key saved to " + pairingPath + ").");
    }

    private static EnrollResult finishWithClientHash(ChipPort chip, String done) throws Exception {
        Optional<byte[]> hash = chip.clientHash();
        if (hash.isEmpty()) {
            return EnrollResult.ok(done + "\nCLIENT HASH unavailable (needs device cert + Tropic ECC).");
        }
        return EnrollResult.ok(done + "\nCLIENT HASH (96 hex):\n" + SeBytes.toHex(hash.get()));
    }

    /** CLIENT CSR dump used by INIT and {@code CSR EXPORT}. Does not sign or install. */
    static byte[] exportClientCsr(ChipPort chip, Certs certs, Path deviceCert) throws Exception {
        byte[] csrPub = chip.clientCsrPub();
        if (csrPub == null) {
            throw new IOException("could not parse device public key");
        }
        if (isAllZero(csrPub)) {
            throw new IOException(
                    "device public key is all zeros (reflash firmware with CLIENT CSR export fix)");
        }
        Path clientDir = deviceCert.getParent() == null ? deviceCert : deviceCert.getParent();
        certs.writeCsrHex(clientDir.resolve("client-csr.hex"), csrPub);
        System.out.println("CLIENT CSR ok (" + csrPub.length + " bytes)");
        return csrPub;
    }

    static EnrollResult insertSignedCsr(ChipPort chip, byte[] certDer) throws Exception {
        SeManage.Reply inserted = chip.manage(
                SeManage.CMD_INSERT_SIGNED_CSR, null, SeManage.encodeDeviceCertBody(certDer));
        if (!inserted.ok()) {
            return EnrollResult.stop("INSERT SIGNED CSR", inserted.describe());
        }
        System.out.println(inserted.describe());
        return EnrollResult.ok(inserted.msg());
    }

    static EnrollResult refuseIfKemProvisioned(ChipPort chip) throws Exception {
        if (chip.tropicKemPub().isPresent()) {
            return EnrollResult.stop("INIT", MSG_KEM_ALREADY_PROVISIONED);
        }
        return EnrollResult.ok("");
    }

    private static void printWizard(Profile profile) {
        System.out.println("Profile: " + profile);
        if (profile == Profile.LAB) {
            System.out.println("""
                    --- Chip INIT LAB ---
                    This will:
                      1. Enroll this UserApp certificate as owner (OWNER SET) if the slot is empty
                         (unsigned USB blob: owner password + owner SPKI + SAE CA).
                         Owner password is for device renew; it is not attempt-locked, so use a strong one.
                      2. Generate Tropic ECC P-256 slot 0 over MANAGE TLS only if empty
                         (occupied slot is left alone; occupancy from TROPIC PUB)
                      3. Set the Tropic PIN (encrypt/decrypt; 8 attempts max) over MANAGE TLS if slot 510 is empty
                      4. Dump CLIENT CSR (on-chip ML-DSA pub) into the client folder and sign it
                         with the local client CA, then INSERT SIGNED CSR (cert only)
                      5. Print CLIENT HASH (96 hex) for copy

                    Pairing is not run; factory SH0 stays. TLS encrypt waits until the signed cert
                    is on the device (this wizard installs it).

                    WARNING: Tropic PIN is for encrypt/decrypt (8 attempts max). Losing it loses the ML-KEM seed / pad unwrap.
                    WARNING: owner password is for device renew and is not attempt-locked — use a strong password.
                    WARNING: occupied KEM slot 510 is not overwritten (INIT will stop).
                    """);
            return;
        }
        System.err.println("""
                WARNING: INIT PROD is the production enrollment path.
                WARNING: it will not sign the device CSR with the lab client CA.
                WARNING: ENCRYPT/DECRYPT/PROVISION stay down until a client-CA-signed cert
                         is installed with INSERT SIGNED CSR (not during this wizard).
                WARNING: pairing (if you choose 1-3) burns factory SH0 and is irreversible
                         on silicon. The pairing private key is written to pairing-key.hex
                         (not printed). PAIRING LOAD restores L3 after an MCU erase; pads
                         and device identity stay lost.
                """);
        System.out.println("""
                --- Chip INIT PROD ---
                This will:
                  1. Enroll this UserApp certificate as owner (OWNER SET) if the slot is empty
                     (unsigned USB blob: owner password + owner SPKI + SAE CA).
                     Owner password is for device renew; it is not attempt-locked, so use a strong one.
                  2. Generate or replace Tropic ECC P-256 slot 0 over MANAGE TLS
                  3. Set the Tropic PIN (encrypt/decrypt; 8 attempts max) over MANAGE TLS
                     (unsigned; owner-pinned, not mTLS)
                  4. Dump CLIENT CSR into the client folder (no local CA sign, no install)
                  5. Optionally write a new X25519 pairing key (slot 1-3, invalidates
                     factory SH0) over MANAGE, or skip with n. The private
                     key is saved to pairing-key.hex next to the device cert (not printed).
                  6. Print CLIENT HASH (96 hex) for copy (needs device cert + Tropic ECC;
                     run INSERT SIGNED CSR after the authority signs the CSR)

                WARNING: Tropic PIN is for encrypt/decrypt (8 attempts max). Losing it loses the ML-KEM seed / pad unwrap.
                WARNING: owner password is for device renew and is not attempt-locked — use a strong password.
                WARNING: PAIRING (1-3) is irreversible on real silicon (factory SH0 is burned).
                WARNING: after PAIRING, an MCU erase needs OWNER SET then PAIRING LOAD to reopen L3.
                WARNING: PAIRING LOAD restores L3 only; pads and the enrolled identity stay lost.
                WARNING: replacing an occupied ECC slot destroys the previous identity key.
                WARNING: occupied KEM slot 510 is not overwritten (INIT will stop).
                """);
    }

    private static byte[] derCert(Path path) throws Exception {
        return PeerCertHash.loadCert(path).getEncoded();
    }

    static String readOwnerPassword(Scanner sc) {
        return readOwnerPassword(sc, OWNER_PASSWORD_PROMPT);
    }

    static String readOwnerPassword(Scanner sc, String prompt) {
        System.out.print(prompt);
        if (!sc.hasNextLine()) {
            return null;
        }
        String pw = sc.nextLine();
        byte[] bytes = pw.getBytes(StandardCharsets.US_ASCII);
        if (!SeManage.passwordOk(bytes)) {
            System.err.println("Owner password must be 8–64 printable ASCII characters.");
            return null;
        }
        System.out.print(OWNER_PASSWORD_CONFIRM_PROMPT);
        if (!sc.hasNextLine()) {
            return null;
        }
        if (!pw.equals(sc.nextLine())) {
            System.err.println("Owner password confirmation did not match.");
            return null;
        }
        return pw;
    }

    private static String readConfirmedPin(Scanner sc, Function<Scanner, String> readPin) {
        String pin = readPin.apply(sc);
        if (pin == null) {
            return null;
        }
        System.out.print(TROPIC_PIN_CONFIRM_PROMPT);
        if (!sc.hasNextLine()) {
            return null;
        }
        String again = sc.nextLine();
        if (!SeManage.pinOk(again) || !pin.equals(again)) {
            System.err.println("Tropic PIN confirmation did not match.");
            return null;
        }
        return pin;
    }

    private static Optional<Integer> readPairingSlot(Scanner sc) {
        while (true) {
            System.out.print("Pairing slot to replace SH0 [1-3], or n to skip: ");
            if (!sc.hasNextLine()) {
                return null;
            }
            Optional<Integer> choice = parsePairingChoice(sc.nextLine());
            if (choice != null) {
                return choice;
            }
            System.err.println("Enter 1, 2, 3, or n to leave the pairing key unchanged.");
        }
    }

    /**
     * {@code 1}/{@code 2}/{@code 3} to pair, empty to skip; {@code null} if invalid.
     */
    static Optional<Integer> parsePairingChoice(String raw) {
        if (raw == null) {
            return null;
        }
        String slot = raw.trim();
        if (slot.equals("1") || slot.equals("2") || slot.equals("3")) {
            return Optional.of(Integer.parseInt(slot));
        }
        if (slot.equalsIgnoreCase("n")) {
            return Optional.empty();
        }
        return null;
    }

    static boolean isInitLab(String raw) {
        return initToken(raw, "INIT LAB", "INITLAB");
    }

    static boolean isInitProd(String raw) {
        return initToken(raw, "INIT PROD", "INITPROD");
    }

    static boolean isCsrExport(String raw) {
        return initToken(raw, "CSR EXPORT", "CSREXPORT");
    }

    private static boolean initToken(String raw, String spaced, String packed) {
        if (raw == null) {
            return false;
        }
        String cmd = raw.strip().toUpperCase(Locale.ROOT).replaceAll("\\s+", " ");
        return cmd.equals(spaced) || cmd.equals(packed);
    }

    static boolean isAllZero(byte[] data) {
        if (data == null) {
            return true;
        }
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    static Path pairingKeyPath(Path deviceCert) {
        Path parent = deviceCert.getParent();
        return (parent == null ? deviceCert : parent).resolve("pairing-key.hex");
    }

    static void writeCsrHex(Path path, byte[] pub) throws IOException {
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(path, SeBytes.toHex(pub) + "\n");
    }

    static void writePairingKeyHex(Path path, int slot, byte[] priv, byte[] pub) throws IOException {
        SeManage.PairingKey key = new SeManage.PairingKey(slot, priv, pub);
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        String body = key.slot() + "\n" + SeBytes.toHex(key.priv()) + "\n" + SeBytes.toHex(key.pub()) + "\n";
        Files.writeString(path, body);
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
        }
    }

    static SeManage.PairingKey readPairingKeyHex(Path path) throws IOException {
        List<String> lines = new ArrayList<>();
        for (String line : Files.readAllLines(path)) {
            String stripped = line.strip();
            if (!stripped.isEmpty()) {
                lines.add(stripped);
            }
        }
        if (lines.size() != 3) {
            throw new IOException("pairing-key.hex must have slot, priv hex, and pub hex");
        }
        int slot;
        try {
            slot = Integer.parseInt(lines.get(0));
        } catch (NumberFormatException e) {
            throw new IOException("pairing-key.hex slot", e);
        }
        try {
            return new SeManage.PairingKey(slot, SeBytes.fromHex(lines.get(1)), SeBytes.fromHex(lines.get(2)));
        } catch (IllegalArgumentException e) {
            throw new IOException("pairing-key.hex", e);
        }
    }

    private static final class FileCerts implements Certs {
        @Override
        public byte[] signLab(Path clientCaP12, String clientCaP12Password, byte[] csrPub, String deviceCn)
                throws Exception {
            return SoftwareLeaf.signRawMlDsa44Leaf(
                    clientCaP12, clientCaP12Password, csrPub, deviceCn).getEncoded();
        }

        @Override
        public void writePem(byte[] certDer, Path path) throws Exception {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            CertificateFactory cf = CertificateFactory.getInstance(
                    "X.509", BouncyCastleProvider.PROVIDER_NAME);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
            SoftwareLeaf.writeCertPem(cert, path);
        }

        @Override
        public Optional<byte[]> loadDerIfPresent(Path path) throws Exception {
            if (!Files.isRegularFile(path)) {
                return Optional.empty();
            }
            return Optional.of(PeerCertHash.loadCert(path).getEncoded());
        }

        @Override
        public void writeCsrHex(Path path, byte[] pub) throws IOException {
            ChipInit.writeCsrHex(path, pub);
        }

        @Override
        public void writePairingKeyHex(Path path, int slot, byte[] priv, byte[] pub) throws IOException {
            ChipInit.writePairingKeyHex(path, slot, priv, pub);
        }

        @Override
        public boolean isRegularFile(Path path) {
            return path != null && Files.isRegularFile(path);
        }
    }
}







