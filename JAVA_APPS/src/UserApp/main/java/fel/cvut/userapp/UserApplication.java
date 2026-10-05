package fel.cvut.userapp;

import fel.cvut.se.EnvSecrets;
import fel.cvut.se.SeBytes;
import fel.cvut.se.SeManage;
import fel.cvut.se.SecureOtp;
import fel.cvut.tls.SoftwareLeaf;
import fel.cvut.tls.SoftwareTls;
import fel.cvut.usb.SeUsbLink;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Scanner;

/**
 * USB console: raw chip commands, OTP encrypt/decrypt, peer hash/add, and chip INIT LAB/PROD.
 * TLS identity is the software ML-DSA PKCS#12 (or PEM fallback) in {@code certs/user/} (no HSM).
 *
 * <p>USB path is {@code USB_SERIAL_PORT}.
 */
public final class UserApplication {

    public static void main(String[] args) throws Exception {
        String serialPort = envOrDefault("USB_SERIAL_PORT", SeUsbLink.DEFAULT_PORT);
        int baudRate = Integer.parseInt(envOrDefault("USB_BAUD_RATE", Integer.toString(SeUsbLink.DEFAULT_BAUD)));

        Path certs = SoftwareTls.certsDir();
        Path ownerCertPath = certPath(certs, "USERAPP_OWNER_CERT", "user/user-cert.pem");
        Path ownerKeyPath = certPath(certs, "USERAPP_OWNER_KEY", "user/user-key.pem");
        Path ownerP12Path = certPath(certs, "USERAPP_OWNER_P12", "user/user.p12");
        Path deviceCertPath = certPath(certs, "USERAPP_DEVICE_CERT", "client/client-cert.pem");
        Path saeCaPath = certPath(certs, "USERAPP_SAE_CA", "ca/root-ca.pem");
        Path clientCaP12Path = certPath(certs, "USERAPP_CLIENT_CA_P12", "ca/client_ca.p12");

        byte[] lastEncryptReply = null;

        try (Scanner sc = new Scanner(System.in);
             UsbSession usb = new UsbSession(serialPort, baudRate)) {
            char[] ownerP12Password = EnvSecrets.envOrScan("USERAPP_OWNER_P12_PASSWORD").toCharArray();
            String clientCaP12Password = EnvSecrets.envOrScan("USERAPP_CLIENT_CA_P12_PASSWORD");

            SSLContext ctx;
            X509Certificate ownerCert;
            try {
                if (Files.isRegularFile(ownerP12Path)) {
                    ctx = SoftwareTls.createContextFromPkcs12(
                            ownerP12Path, ownerP12Password, SoftwareTls.clientCaPem());
                    ownerCert = SoftwareTls.softwareLeafFromPkcs12(ownerP12Path, ownerP12Password);
                } else {
                    ctx = SoftwareTls.createContextFromPem(
                            ownerCertPath, ownerKeyPath, SoftwareTls.clientCaPem());
                    ownerCert = SoftwareTls.softwareLeafFromPem(ownerCertPath);
                }
            } finally {
                java.util.Arrays.fill(ownerP12Password, '\0');
            }
            byte[] ownerSpki = PeerCertHash.rawSpkiBits(ownerCert);
            String deviceCn = deviceCnFor(deviceCertPath);

            usb.require();
            while (true) {
                System.out.print("APP [ENCRYPT/DECRYPT/OTP STATUS/PEER/INIT LAB/INIT PROD/INSERT SIGNED CSR/OWNER/REPLACE/quit] or chip line: ");
                System.out.flush();
                if (!sc.hasNextLine()) {
                    return;
                }
                String stripped = sc.nextLine().strip();
                if (stripped.isEmpty()) {
                    continue;
                }
                if (isQuit(stripped)) {
                    return;
                }

                try {
                    byte[] encryptReply = dispatch(
                            sc, usb, ctx, stripped, lastEncryptReply,
                            deviceCertPath, saeCaPath, clientCaP12Path, clientCaP12Password,
                            deviceCn, ownerSpki);
                    if (encryptReply != null) {
                        lastEncryptReply = encryptReply;
                    }
                } catch (Exception e) {
                    System.err.println("Command failed: " + e.getMessage());
                }
            }
        }
    }

    /**
     * @return encrypt reply bytes when ENCRYPT succeeds; otherwise {@code null}
     *         (caller keeps the previous {@code lastEncryptReply})
     */
    private static byte[] dispatch(
            Scanner sc,
            UsbSession usb,
            SSLContext ctx,
            String stripped,
            byte[] lastEncryptReply,
            Path deviceCertPath,
            Path saeCaPath,
            Path clientCaP12Path,
            String clientCaP12Password,
            String deviceCn,
            byte[] ownerSpki
    ) throws Exception {
        ChipService chip = new ChipService(usb.require(), ctx);
        String raw = stripped.toUpperCase(Locale.ROOT);

        if (raw.equals("ENCRYPT") || raw.equals("E")) {
            return runEncryptFlow(sc, chip);
        }
        if (raw.equals("DECRYPT") || raw.equals("D")) {
            runDecryptFlow(sc, chip, lastEncryptReply);
            return null;
        }
        if (raw.equals("STATUS") || raw.equals("OTP STATUS") || raw.equals("OTPSTATUS")) {
            printResult(chip.otpStatus());
            return null;
        }
        if (isInsertSignedCsr(raw)) {
            runInsertSignedCsr(chip, deviceCertPath);
            return null;
        }
        if (ChipInit.isInitLab(raw)) {
            ChipInit.run(sc, usb.require(), ConsoleIo::readPin, ctx,
                    deviceCertPath, saeCaPath, clientCaP12Path, clientCaP12Password,
                    deviceCn, ownerSpki, ChipInit.Profile.LAB);
            return null;
        }
        if (ChipInit.isInitProd(raw)) {
            ChipInit.run(sc, usb.require(), ConsoleIo::readPin, ctx,
                    deviceCertPath, saeCaPath, clientCaP12Path, clientCaP12Password,
                    deviceCn, ownerSpki, ChipInit.Profile.PROD);
            return null;
        }
        if (raw.equals("INIT") || raw.equals("INIT SAFE") || raw.equals("INITSAFE")) {
            System.err.println("Use INIT LAB or INIT PROD.");
            System.err.println("INIT LAB signs the on-chip CSR with the local client CA and never pairs.");
            System.err.println("INIT PROD does not sign locally and may burn factory SH0 — confirm before using it.");
            return null;
        }
        if (raw.equals("OWNER")) {
            runOwnerSet(sc, chip, saeCaPath, ownerSpki);
            return null;
        }
        if (raw.equals("REPLACE")) {
            runOwnerReplace(sc, chip, ownerSpki);
            return null;
        }
        if (raw.equals("PEER") || raw.startsWith("PEER ")) {
            PeerCommands.run(sc, chip, stripped);
            return null;
        }
        runRawCommand(chip, stripped);
        return null;
    }

    private static void runRawCommand(ChipService chip, String line) throws Exception {
        if (isTlsArming(line)) {
            System.err.println("TLS-arming commands (PROVISION/ENCRYPT/DECRYPT/MANAGE) switch "
                    + "the pipe to opaque TLS. Use APP ENCRYPT/DECRYPT/PEER/INIT, or TerminalBridge "
                    + "for provision.");
            return;
        }
        printResult(chip.transact(line));
    }

    private static byte[] runEncryptFlow(Scanner sc, ChipService chip) throws Exception {
        String pin = ConsoleIo.readPin(sc);
        if (pin == null) {
            return null;
        }
        String message = ConsoleIo.readLine(sc, "Message: ");
        if (message == null) {
            return null;
        }
        if (message.isEmpty()) {
            System.err.println("Message must not be empty.");
            return null;
        }
        try {
            byte[] raw = chip.encrypt(pin, message);
            System.out.println("OK encrypt reply (hex):\n" + SeBytes.toHex(raw));
            return raw;
        } catch (SecureOtp.OtpException e) {
            System.err.println(e.getMessage());
            return null;
        }
    }

    private static void runDecryptFlow(Scanner sc, ChipService chip, byte[] lastEncryptReply)
            throws Exception {
        String pin = ConsoleIo.readPin(sc);
        if (pin == null) {
            return;
        }
        byte[] decryptReplyRaw = ConsoleIo.readEncryptReplyHex(sc, lastEncryptReply);
        if (decryptReplyRaw == null) {
            return;
        }
        try {
            byte[] plaintext = chip.decrypt(pin, decryptReplyRaw);
            System.out.println("OK plaintext:\n" + new String(plaintext, StandardCharsets.UTF_8));
        } catch (SecureOtp.OtpException e) {
            System.err.println(e.getMessage());
        }
    }

    private static void runOwnerSet(
            Scanner sc, ChipService chip, Path saeCa, byte[] ownerSpki
    ) throws Exception {
        String pw = ChipInit.readOwnerPassword(sc);
        if (pw == null) {
            return;
        }
        byte[] pwBytes = pw.getBytes(StandardCharsets.US_ASCII);
        byte[] saeCaDer = PeerCertHash.loadCert(saeCa).getEncoded();
        switch (chip.ownerSet(pwBytes, ownerSpki, saeCaDer)) {
            case ChipInit.OwnerSetResult.AlreadyEnrolled ignored ->
                    System.err.println("OWNER SET refused (already enrolled). Use REPLACE.");
            case ChipInit.OwnerSetResult.Failed failed ->
                    System.err.println("OWNER SET failed: " + failed.detail());
            case ChipInit.OwnerSetResult.Ok ignored ->
                    System.out.println("OK OWNER SET");
        }
    }

    private static void runOwnerReplace(Scanner sc, ChipService chip, byte[] ownerSpki)
            throws Exception {
        String oldPw = ConsoleIo.readRequired(sc, "Current owner password (device renew): ");
        if (oldPw == null) {
            return;
        }
        String newPw = ChipInit.readOwnerPassword(sc, ChipInit.NEW_OWNER_PASSWORD_PROMPT);
        if (newPw == null) {
            return;
        }
        byte[] newBytes = newPw.getBytes(StandardCharsets.US_ASCII);
        SeManage.Reply r = chip.ownerReplace(
                oldPw.getBytes(StandardCharsets.US_ASCII), newBytes, ownerSpki);
        if (!r.ok()) {
            if (r.status() == SeManage.PW_FAIL) {
                System.err.println("OWNER REPLACE failed: current owner password is wrong "
                        + "(each lab device keeps its own password from the INIT/OWNER that enrolled it).");
            } else {
                System.err.println("OWNER REPLACE failed: " + r.msg());
            }
            return;
        }
        System.out.println("OK OWNER REPLACE");
    }

    private static void runInsertSignedCsr(ChipService chip, Path deviceCert) throws Exception {
        if (deviceCert == null || !Files.isRegularFile(deviceCert)) {
            System.err.println("INSERT SIGNED CSR needs a signed device cert at USERAPP_DEVICE_CERT ("
                    + deviceCert + ").");
            return;
        }
        byte[] certDer = PeerCertHash.loadCert(deviceCert).getEncoded();
        SeManage.Reply r = chip.insertSignedCsr(certDer);
        if (!r.ok()) {
            System.err.println("INSERT SIGNED CSR failed: " + r.describe());
            return;
        }
        System.out.println("OK INSERT SIGNED CSR" + (r.msg().isBlank() ? "" : ": " + r.msg()));
    }

    private static void printResult(String reply) {
        if (reply == null || reply.isBlank()) {
            System.out.println("(no reply)");
            return;
        }
        System.out.println(reply);
    }

    private static boolean isInsertSignedCsr(String raw) {
        if (raw == null) {
            return false;
        }
        String cmd = raw.strip().replaceAll("\\s+", " ");
        return cmd.equals("INSERT SIGNED CSR") || cmd.equals("INSERTSIGNEDCSR");
    }

    private static boolean isQuit(String raw) {
        String upper = raw.strip().toUpperCase(Locale.ROOT);
        return upper.equals("QUIT") || upper.equals("Q") || upper.equals("EXIT");
    }

    private static boolean isTlsArming(String line) {
        String first = line.strip().split("\\s+", 2)[0];
        return first.equalsIgnoreCase("PROVISION")
                || first.equalsIgnoreCase("ENCRYPT")
                || first.equalsIgnoreCase("DECRYPT")
                || first.equalsIgnoreCase("MANAGE");
    }

    private static String deviceCnFor(Path deviceCert) {
        Path parent = deviceCert.getParent();
        if (parent != null && "client2".equals(parent.getFileName().toString())) {
            return SoftwareLeaf.DEVICE_CLIENT_CN_2;
        }
        return SoftwareLeaf.DEVICE_CLIENT_CN;
    }

    private static Path certPath(Path certsDir, String env, String defaultRel) {
        String spec = envOrDefault(env, defaultRel);
        Path path = Path.of(spec);
        return path.isAbsolute() ? path.normalize() : certsDir.resolve(spec).normalize();
    }

    private static String envOrDefault(String name, String defaultValue) {
        String v = System.getenv(name);
        return (v == null || v.isBlank()) ? defaultValue : v.trim();
    }

    /** Holds CDC for chip console / INIT / OTP for the life of this process. */
    private static final class UsbSession implements AutoCloseable {
        private final String serialPort;
        private final int baudRate;
        private SeUsbLink link;

        private UsbSession(String serialPort, int baudRate) {
            this.serialPort = serialPort;
            this.baudRate = baudRate;
        }

        private SeUsbLink require() throws InterruptedException, IOException {
            if (link != null && !link.isOpen()) {
                close();
            }
            if (link == null) {
                link = SeUsbLink.open(serialPort, baudRate);
            }
            return link;
        }

        @Override
        public void close() {
            if (link != null) {
                link.close();
                link = null;
            }
        }
    }
}
