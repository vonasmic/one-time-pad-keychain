package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeManage;
import fel.cvut.se.SeUsbDump;
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

    private static final String HASH_PROMPT = "Peer cert hash (96 hex): ";

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

        char[] p12Password = envOrDefault("USERAPP_OWNER_P12_PASSWORD", "password").toCharArray();
        SSLContext ctx;
        X509Certificate ownerCert;
        try {
            if (Files.isRegularFile(ownerP12Path)) {
                ctx = SoftwareTls.createContextFromPkcs12(ownerP12Path, p12Password, SoftwareTls.clientCaPem());
                ownerCert = SoftwareTls.softwareLeafFromPkcs12(ownerP12Path, p12Password);
            } else {
                ctx = SoftwareTls.createContextFromPem(ownerCertPath, ownerKeyPath, SoftwareTls.clientCaPem());
                ownerCert = SoftwareTls.softwareLeafFromPem(ownerCertPath);
            }
        } finally {
            java.util.Arrays.fill(p12Password, '\0');
        }
        byte[] ownerSpki = PeerCertHash.rawSpkiBits(ownerCert);
        String deviceCn = deviceCnFor(deviceCertPath);

        byte[] lastEncryptReply = null;

        try (Scanner sc = new Scanner(System.in);
             UsbSession usb = new UsbSession(serialPort, baudRate)) {
            usb.require();
            while (true) {
                System.out.print("APP [ENCRYPT/DECRYPT/LEFT/PEER/INIT LAB/INIT PROD/OWNER/REPLACE/quit] or chip line: ");
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
                String raw = stripped.toUpperCase(Locale.ROOT);

                try {
                    ChipService chip = new ChipService(usb.require(), ctx);
                    if (raw.equals("ENCRYPT") || raw.equals("E")) {
                        byte[] reply = runEncryptFlow(sc, chip);
                        if (reply != null) {
                            lastEncryptReply = reply;
                        }
                    } else if (raw.equals("DECRYPT") || raw.equals("D")) {
                        runDecryptFlow(sc, chip, lastEncryptReply);
                    } else if (raw.equals("LEFT") || raw.equals("OTP LEFT")) {
                        printDump(chip.otpLeft());
                    } else if (ChipInit.isInitLab(raw)) {
                        ChipInit.run(sc, usb.require(), UserApplication::readPin, ctx,
                                deviceCertPath, saeCaPath, clientCaP12Path, deviceCn, ownerSpki,
                                ChipInit.Profile.LAB);
                    } else if (ChipInit.isInitProd(raw)) {
                        ChipInit.run(sc, usb.require(), UserApplication::readPin, ctx,
                                deviceCertPath, saeCaPath, clientCaP12Path, deviceCn, ownerSpki,
                                ChipInit.Profile.PROD);
                    } else if (raw.equals("INIT") || raw.equals("INIT SAFE") || raw.equals("INITSAFE")) {
                        System.err.println("Use INIT LAB or INIT PROD.");
                        System.err.println("INIT LAB signs the on-chip CSR with the local client CA and never pairs.");
                        System.err.println("INIT PROD does not sign locally and may burn factory SH0 — confirm before using it.");
                    } else if (raw.equals("OWNER")) {
                        runOwnerSet(sc, chip, saeCaPath, ownerSpki);
                    } else if (raw.equals("REPLACE")) {
                        runOwnerReplace(sc, chip, ownerSpki);
                    } else if (raw.equals("PEER") || raw.startsWith("PEER ")) {
                        runPeer(sc, chip, stripped);
                    } else {
                        runRawCommand(chip, stripped);
                    }
                } catch (Exception e) {
                    System.err.println("Command failed: " + e.getMessage());
                }
            }
        }
    }

    private static void runRawCommand(ChipService chip, String line) throws Exception {
        if (isTlsArming(line)) {
            System.err.println("TLS-arming commands (PROVISION/ENCRYPT/DECRYPT/MANAGE) switch "
                    + "the pipe to opaque TLS. Use APP ENCRYPT/DECRYPT/PEER/INIT, or TerminalBridge "
                    + "for provision.");
            return;
        }
        if (isDumpCommand(line)) {
            printDump(chip.dump(line));
            return;
        }
        chip.transact(line);
    }

    private static byte[] runEncryptFlow(Scanner sc, ChipService chip) throws Exception {
        String pin = readPin(sc);
        if (pin == null) {
            return null;
        }
        System.out.print("Message: ");
        if (!sc.hasNextLine()) {
            return null;
        }
        String message = sc.nextLine();
        if (message.isEmpty()) {
            System.err.println("Message must not be empty.");
            return null;
        }
        try {
            byte[] raw = chip.encrypt(pin, message);
            System.out.println("Encrypt reply (hex): " + SeBytes.toHex(raw));
            return raw;
        } catch (SecureOtp.OtpException e) {
            System.err.println(e.getMessage());
            return null;
        }
    }

    private static void runDecryptFlow(Scanner sc, ChipService chip, byte[] lastEncryptReply)
            throws Exception {
        String pin = readPin(sc);
        if (pin == null) {
            return;
        }
        byte[] decryptReplyRaw = readEncryptReplyHex(sc, lastEncryptReply);
        if (decryptReplyRaw == null) {
            return;
        }
        try {
            byte[] plaintext = chip.decrypt(pin, decryptReplyRaw);
            System.out.println("Plaintext: " + new String(plaintext, StandardCharsets.UTF_8));
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
            case ChipInit.OwnerSetResult.Ok ignored -> {
            }
        }
    }

    private static void runOwnerReplace(Scanner sc, ChipService chip, byte[] ownerSpki)
            throws Exception {
        String oldPw = readRequired(sc, "Current owner password (device renew): ");
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
        }
    }

    private static void runPeer(Scanner sc, ChipService chip, String command) throws Exception {
        String afterPeer = command.length() > 4 ? command.substring(4).strip() : "";
        if (afterPeer.isEmpty()) {
            System.out.print("PEER [ADD/REMOVE/LIST]: ");
            if (!sc.hasNextLine()) {
                return;
            }
            afterPeer = sc.nextLine().strip();
        }
        String sub = afterPeer.toUpperCase(Locale.ROOT);
        if (sub.equals("LIST") || sub.equals("L")) {
            printDump(chip.peerList());
            return;
        }
        if (sub.equals("REMOVE") || sub.equals("R") || sub.startsWith("REMOVE")) {
            String name = peerArg(afterPeer, "REMOVE");
            if (name.isEmpty()) {
                name = readRequired(sc, "Nickname: ");
                if (name == null) {
                    return;
                }
            }
            if (!PeerCertHash.validNickname(name)) {
                System.err.println("Nickname must be 1-16 of [A-Za-z0-9_.-].");
                return;
            }
            String pin = readPin(sc);
            if (pin == null) {
                return;
            }
            SeManage.Reply r = chip.peerRemove(pin, name);
            if (!r.ok()) {
                System.err.println("PEER REMOVE failed: " + r.msg());
            }
            return;
        }
        if (sub.equals("ADD") || sub.equals("A") || sub.startsWith("ADD")) {
            String name = peerArg(afterPeer, "ADD");
            if (name.isEmpty()) {
                name = readRequired(sc, "Nickname: ");
                if (name == null) {
                    return;
                }
            }
            if (!PeerCertHash.validNickname(name)) {
                System.err.println("Nickname must be 1-16 of [A-Za-z0-9_.-].");
                return;
            }
            String hashInput = readRequired(sc, HASH_PROMPT);
            if (hashInput == null) {
                return;
            }
            String hash;
            try {
                hash = PeerCertHash.parseHashHex(hashInput);
            } catch (IllegalArgumentException ex) {
                System.err.println(ex.getMessage());
                return;
            }
            System.out.println("PEER hash: " + hash);
            String pin = readPin(sc);
            if (pin == null) {
                return;
            }
            SeManage.Reply r = chip.peerAdd(pin, name, SeBytes.fromHex(hash));
            if (!r.ok()) {
                System.err.println("PEER ADD failed: " + r.msg());
            }
            return;
        }
        System.err.println("Unknown PEER subcommand. Use ADD, REMOVE, or LIST.");
    }

    /** Remainder after {@code ADD}/{@code REMOVE}, preserving nickname case. */
    private static String peerArg(String afterPeer, String verb) {
        if (afterPeer.length() <= verb.length()) {
            return "";
        }
        if (!afterPeer.regionMatches(true, 0, verb, 0, verb.length())) {
            return "";
        }
        return afterPeer.substring(verb.length()).strip();
    }

    private static byte[] readEncryptReplyHex(Scanner sc, byte[] lastEncryptReply) {
        System.out.print("Encrypt reply hex (empty = last): ");
        if (!sc.hasNextLine()) {
            return null;
        }
        String line = sc.nextLine().trim();
        if (line.isEmpty()) {
            if (lastEncryptReply == null || lastEncryptReply.length == 0) {
                System.err.println("No previous encrypt reply. Paste the hex from ENCRYPT.");
                return null;
            }
            return lastEncryptReply;
        }
        try {
            byte[] raw = SeBytes.fromHex(line);
            SecureOtp.decodeEncryptReply(raw);
            return raw;
        } catch (Exception e) {
            System.err.println("Invalid encrypt reply: " + e.getMessage());
            return null;
        }
    }

    static String readPin(Scanner sc) {
        while (true) {
            System.out.print(ChipInit.TROPIC_PIN_PROMPT);
            if (!sc.hasNextLine()) {
                return null;
            }
            String pin = sc.nextLine();
            if (SeManage.pinOk(pin)) {
                return pin;
            }
            System.err.println("Tropic PIN must be 8 to 16 printable ASCII characters.");
        }
    }

    private static String readRequired(Scanner sc, String prompt) {
        System.out.print(prompt);
        if (!sc.hasNextLine()) {
            return null;
        }
        String value = sc.nextLine().strip();
        if (value.isEmpty()) {
            System.err.println("Value must not be empty.");
            return null;
        }
        return value;
    }

    private static boolean isQuit(String raw) {
        String upper = raw.strip().toUpperCase(Locale.ROOT);
        return upper.equals("QUIT") || upper.equals("Q") || upper.equals("EXIT");
    }

    private static boolean isDumpCommand(String line) {
        String u = line.strip().toUpperCase(Locale.ROOT);
        return u.equals("OWNER SET")
                || u.equals("PEER LIST")
                || u.equals("CLIENT HASH")
                || u.equals("CLIENT CSR")
                || u.equals("TROPIC PUB")
                || u.equals("TROPIC KEM PUB")
                || u.equals("TROPIC OTP LEFT");
    }

    private static void printDump(SeUsbDump dump) {
        if (dump == null) {
            System.err.println("failed");
            return;
        }
        if (dump.refused()) {
            System.out.println("refused");
            return;
        }
        if (dump.empty()) {
            System.out.println("empty");
            return;
        }
        if (!dump.ok()) {
            System.err.println("failed");
            return;
        }
        if (dump.body.length == 0) {
            System.out.println("ok");
            return;
        }
        int[] otp = dump.otpLeft();
        if (otp != null) {
            System.out.println("enc " + otp[0] + "/" + otp[1] + " dec " + otp[2] + "/" + otp[3]);
            return;
        }
        var peers = dump.peers();
        if (peers != null) {
            if (peers.isEmpty()) {
                System.out.println("empty");
                return;
            }
            for (SeUsbDump.Peer p : peers) {
                System.out.println(p.name() + " " + SeBytes.toHex(p.hash()));
            }
            return;
        }
        System.out.println(SeBytes.toHex(dump.body));
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
