package fel.cvut.userapp;

import fel.cvut.terminal.AppLogging;
import fel.cvut.se.SeBytes;
import fel.cvut.se.SeConstants;
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
            "ML-KEM is already provisioned (TROPIC KEM PUB shows the KEM slot). "
                    + "INIT LAB and INIT PROD cannot change the Tropic PIN. "
                    + "Use REPLACE to change the owner password. "
                    + "Use PEER ADD, PEER REMOVE, or INSERT SIGNED CSR for other enrollment changes.";

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
            ConsoleStyle.err("INIT " + profile + " refused: " + preflight.message());
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

        ConsoleStyle.prompt("Type YES to continue (anything else cancels): ");
        if (!sc.hasNextLine()) {
            return;
        }
        if (!"YES".equals(sc.nextLine().trim())) {
            ConsoleStyle.warn("INIT " + profile + " cancelled.");
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
            if ("INIT".equals(result.stoppedAt())) {
                ConsoleStyle.err("INIT " + profile + " refused: " + result.message());
            } else {
                ConsoleStyle.err("INIT " + profile + " stopped during "
                        + stepLabel(result.stoppedAt()) + ": " + result.message());
            }
        } else if (result.message() != null && !result.message().isBlank()) {
            ConsoleStyle.okBlock(result.message());
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
                ConsoleStyle.warn("Owner already enrolled");
            }
            case OwnerSetResult.Ok ignored -> {
                ConsoleStyle.ok("Owner enrolled");
            }
        }

        Optional<byte[]> eccPub = chip.tropicPub();
        if (eccPub.isPresent()) {
            if (profile.replaceOccupiedEcc()) {
                SeManage.Reply replaced = chip.manage(SeManage.CMD_KEYGEN, null, null);
                if (!replaced.ok()) {
                    return EnrollResult.stop("KEYGEN", replaced.describe());
                }
                ConsoleStyle.ok("Tropic ECC key replaced");
            } else {
                ConsoleStyle.warn("Tropic ECC key left unchanged (slot occupied)");
            }
        } else {
            SeManage.Reply generated = chip.manage(SeManage.CMD_KEYGEN, null, null);
            if (!generated.ok()) {
                return EnrollResult.stop("KEYGEN", generated.describe());
            }
            ConsoleStyle.ok("Tropic ECC key generated");
        }

        SeManage.Reply kem = chip.manage(SeManage.CMD_KEM_INIT, req.pin(), null);
        if (!kem.ok()) {
            return EnrollResult.stop("KEM INIT", kem.describe());
        }
        ConsoleStyle.ok("Tropic PIN set");

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
            ConsoleStyle.warn("INIT PROD: CSR written; run INSERT SIGNED CSR after the authority signs it.");
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
        ConsoleStyle.ok("Pairing key saved to " + pairingPath);
        return finishWithClientHash(chip,
                "INIT PROD finished (pairing key saved to " + pairingPath + ").");
    }

    private static EnrollResult finishWithClientHash(ChipPort chip, String done) throws Exception {
        Optional<byte[]> hash = chip.clientHash();
        if (hash.isEmpty()) {
            return EnrollResult.ok(done + "\nClient hash unavailable (needs a device cert and a Tropic ECC key).");
        }
        return EnrollResult.ok(done + "\nClient hash (96 hex):\n" + SeBytes.toHex(hash.get()));
    }

    /** CLIENT CSR dump used by INIT and {@code CSR EXPORT}. Does not sign or install. */
    static byte[] exportClientCsr(ChipPort chip, Certs certs, Path deviceCert) throws Exception {
        byte[] csrPub = chip.clientCsrPub();
        if (csrPub == null) {
            throw new IOException("could not parse device public key");
        }
        if (csrPub.length != SeConstants.MLDSA_PUB_LEN) {
            throw new IOException("CLIENT CSR truncated (" + csrPub.length + " of "
                    + SeConstants.MLDSA_PUB_LEN + " bytes)");
        }
        if (isAllZero(csrPub)) {
            throw new IOException(
                    "device public key is all zeros (reflash firmware with CLIENT CSR export fix)");
        }
        Path clientDir = deviceCert.getParent() == null ? deviceCert : deviceCert.getParent();
        certs.writeCsrHex(clientDir.resolve("client-csr.hex"), csrPub);
        ConsoleStyle.ok("Client CSR written (" + csrPub.length + " bytes)");
        return csrPub;
    }

    static EnrollResult insertSignedCsr(ChipPort chip, byte[] certDer) throws Exception {
        SeManage.Reply inserted = chip.manage(
                SeManage.CMD_INSERT_SIGNED_CSR, null, SeManage.encodeDeviceCertBody(certDer));
        if (!inserted.ok()) {
            return EnrollResult.stop("INSERT SIGNED CSR", inserted.describe());
        }
        ConsoleStyle.ok("INSERT SIGNED CSR ok");
        return EnrollResult.ok(inserted.msg());
    }

    static EnrollResult refuseIfKemProvisioned(ChipPort chip) throws Exception {
        if (chip.tropicKemPub().isPresent()) {
            return EnrollResult.stop("INIT", MSG_KEM_ALREADY_PROVISIONED);
        }
        return EnrollResult.ok("");
    }

    /** User-facing name for an internal enroll step. Stop tokens stay stable for tests. */
    private static String stepLabel(String stoppedAt) {
        return switch (stoppedAt) {
            case "OWNER SET" -> "owner enrollment";
            case "KEYGEN" -> "Tropic ECC key";
            case "KEM INIT" -> "Tropic PIN";
            case "CLIENT CSR" -> "CSR export";
            case "INSERT SIGNED CSR" -> "INSERT SIGNED CSR";
            case "PAIRING" -> "pairing key";
            default -> stoppedAt;
        };
    }

    private static void printWizard(Profile profile) {
        ConsoleStyle.section("Profile: " + profile);
        if (profile == Profile.LAB) {
            AppLogging.terminalOut().println("""
                    --- INIT LAB ---
                    This will:
                      1. Enroll this UserApp certificate as owner if the slot is empty
                         (owner password + this app's key + SAE CA).
                         The owner password is for REPLACE; it is not attempt-locked, so use a strong one.
                      2. Generate the Tropic ECC key only if the slot is empty
                         (an occupied slot is left alone; check with TROPIC PUB)
                      3. Set the Tropic PIN used by ENCRYPT and DECRYPT (8 attempts max) if the KEM slot is empty
                      4. Write the on-chip CSR into the client folder, sign it with the local client CA,
                         and install it (same result as INSERT SIGNED CSR)
                      5. Print the client hash (same as CLIENT HASH)

                    Pairing is not run; factory SH0 stays. ENCRYPT and DECRYPT wait until the signed
                    cert is on the device (this wizard installs it).

                    WARNING: the Tropic PIN is for ENCRYPT and DECRYPT (8 attempts max). Losing it loses the ML-KEM seed / pad unwrap.
                    WARNING: the owner password is for REPLACE and is not attempt-locked — use a strong password.
                    WARNING: an occupied KEM slot is not overwritten (INIT LAB will stop).
                    """);
            return;
        }
        ConsoleStyle.warn("""
                WARNING: INIT PROD is the production enrollment path.
                WARNING: it will not sign the device CSR with the lab client CA.
                WARNING: ENCRYPT, DECRYPT, and provisioning stay down until a signed cert
                         is installed with INSERT SIGNED CSR (not during this wizard).
                WARNING: choosing pairing slot 1-3 burns factory SH0 and is irreversible
                         on silicon. The pairing private key is written to pairing-key.hex
                         (not printed). After an MCU erase, OWNER then PAIRING LOAD restores
                         L3; pads and device identity stay lost.
                """);
        AppLogging.terminalOut().println("""
                --- INIT PROD ---
                This will:
                  1. Enroll this UserApp certificate as owner if the slot is empty
                     (owner password + this app's key + SAE CA).
                     The owner password is for REPLACE; it is not attempt-locked, so use a strong one.
                  2. Generate or replace the Tropic ECC key
                  3. Set the Tropic PIN used by ENCRYPT and DECRYPT (8 attempts max)
                  4. Write the on-chip CSR into the client folder (no local CA sign, no install)
                  5. Optionally write a new pairing key in slot 1-3 (burns factory SH0), or skip with n.
                     The private key is saved to pairing-key.hex next to the device cert (not printed).
                  6. Print the client hash (same as CLIENT HASH) when a device cert and Tropic ECC exist.
                     After an authority signs the CSR, run INSERT SIGNED CSR.

                WARNING: the Tropic PIN is for ENCRYPT and DECRYPT (8 attempts max). Losing it loses the ML-KEM seed / pad unwrap.
                WARNING: the owner password is for REPLACE and is not attempt-locked — use a strong password.
                WARNING: pairing slot 1-3 is irreversible on real silicon (factory SH0 is burned).
                WARNING: after pairing, an MCU erase needs OWNER, then PAIRING LOAD, to reopen L3.
                WARNING: PAIRING LOAD restores L3 only; pads and the enrolled identity stay lost.
                WARNING: replacing an occupied ECC slot destroys the previous identity key.
                WARNING: an occupied KEM slot is not overwritten (INIT PROD will stop).
                """);
    }

    private static byte[] derCert(Path path) throws Exception {
        return PeerCertHash.loadCert(path).getEncoded();
    }

    static String readOwnerPassword(Scanner sc) {
        return readOwnerPassword(sc, OWNER_PASSWORD_PROMPT);
    }

    static String readOwnerPassword(Scanner sc, String prompt) {
        ConsoleStyle.prompt(prompt);
        if (!sc.hasNextLine()) {
            return null;
        }
        String pw = sc.nextLine();
        byte[] bytes = pw.getBytes(StandardCharsets.US_ASCII);
        if (!SeManage.passwordOk(bytes)) {
            ConsoleStyle.err("Owner password must be 8–64 printable ASCII characters.");
            return null;
        }
        ConsoleStyle.prompt(OWNER_PASSWORD_CONFIRM_PROMPT);
        if (!sc.hasNextLine()) {
            return null;
        }
        if (!pw.equals(sc.nextLine())) {
            ConsoleStyle.err("Owner password confirmation did not match.");
            return null;
        }
        return pw;
    }

    private static String readConfirmedPin(Scanner sc, Function<Scanner, String> readPin) {
        String pin = readPin.apply(sc);
        if (pin == null) {
            return null;
        }
        ConsoleStyle.prompt(TROPIC_PIN_CONFIRM_PROMPT);
        if (!sc.hasNextLine()) {
            return null;
        }
        String again = sc.nextLine();
        if (!SeManage.pinOk(again) || !pin.equals(again)) {
            ConsoleStyle.err("Tropic PIN confirmation did not match.");
            return null;
        }
        return pin;
    }

    private static Optional<Integer> readPairingSlot(Scanner sc) {
        while (true) {
            ConsoleStyle.prompt("Pairing slot to replace SH0 [1-3], or n to skip: ");
            if (!sc.hasNextLine()) {
                return null;
            }
            Optional<Integer> choice = parsePairingChoice(sc.nextLine());
            if (choice != null) {
                return choice;
            }
            ConsoleStyle.err("Enter 1, 2, 3, or n to leave the pairing key unchanged.");
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







