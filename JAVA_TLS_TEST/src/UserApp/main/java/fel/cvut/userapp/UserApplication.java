package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SecureOtp;
import fel.cvut.tls.NodeTls;
import fel.cvut.usb.SeUsbLink;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Scanner;
import java.util.regex.Pattern;

/**
 * USB console: raw chip commands, OTP encrypt/decrypt, peer hash/add, and chip INIT.
 * TLS identity is the software ML-DSA PEM bundle in {@code certs/user/} (no HSM).
 *
 * <p>USB path is {@code USB_SERIAL_PORT}.
 */
public final class UserApplication {

    private static final Pattern PIN = Pattern.compile("[0-9]{4,8}");
    private static final String HASH_PROMPT = "Peer cert hash (96 hex): ";

    public static void main(String[] args) throws Exception {
        String serialPort = envOrDefault("USB_SERIAL_PORT", SeUsbLink.DEFAULT_PORT);
        int baudRate = Integer.parseInt(envOrDefault("USB_BAUD_RATE", Integer.toString(SeUsbLink.DEFAULT_BAUD)));

        Path certs = NodeTls.certsDir();
        Path ownerCertPath = certPath(certs, "USERAPP_OWNER_CERT", "user/user-cert.pem");
        Path ownerKeyPath = certPath(certs, "USERAPP_OWNER_KEY", "user/user-key.pem");
        Path deviceCertPath = certPath(certs, "USERAPP_DEVICE_CERT", "client/client-cert.pem");
        Path deviceKeyPath = certPath(certs, "USERAPP_DEVICE_KEY", "client/client-key.pem");
        Path saeCaPath = certPath(certs, "USERAPP_SAE_CA", "ca/root-ca.pem");
        Path pairingKeyPath = pairingKeyPath(certs, deviceCertPath);

        SSLContext ctx = NodeTls.createContextFromPem(ownerCertPath, ownerKeyPath, NodeTls.clientCaPem());
        X509Certificate ownerCert = PeerCertHash.loadCert(ownerCertPath);
        byte[] ownerSpki = PeerCertHash.rawSpkiBits(ownerCert);

        byte[] lastEncryptReply = null;

        try (Scanner sc = new Scanner(System.in);
             UsbSession usb = new UsbSession(serialPort, baudRate)) {
            usb.require();
            while (true) {
                System.out.print("APP [ENCRYPT/DECRYPT/LEFT/PEER/INIT/OWNER/REPLACE/quit] or chip line: ");
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
                    if (raw.equals("ENCRYPT") || raw.equals("E")) {
                        byte[] reply = runEncryptFlow(sc, usb, ctx);
                        if (reply != null) {
                            lastEncryptReply = reply;
                        }
                    } else if (raw.equals("DECRYPT") || raw.equals("D")) {
                        runDecryptFlow(sc, usb, ctx, lastEncryptReply);
                    } else if (raw.equals("LEFT") || raw.equals("OTP LEFT")) {
                        usb.require().transact("TROPIC OTP LEFT");
                    } else if (raw.equals("INIT")) {
                        ChipInit.run(sc, usb.require(), UserApplication::readPin, ctx,
                                deviceCertPath, deviceKeyPath, saeCaPath, ownerSpki, pairingKeyPath);
                    } else if (raw.equals("OWNER")) {
                        runOwnerSet(sc, usb, deviceCertPath, deviceKeyPath, saeCaPath, ownerSpki);
                    } else if (raw.equals("REPLACE")) {
                        runOwnerReplace(sc, usb, ctx, ownerSpki);
                    } else if (raw.equals("PEER") || raw.startsWith("PEER ")) {
                        runPeer(sc, usb, stripped, ctx);
                    } else {
                        runRawCommand(usb, stripped);
                    }
                } catch (Exception e) {
                    System.err.println("Command failed: " + e.getMessage());
                    if (e.getMessage() != null
                            && e.getMessage().toLowerCase(Locale.ROOT).contains("no owner")) {
                        System.err.println("No owner enrolled. Use INIT or OWNER, then retry.");
                    }
                }
            }
        }
    }

    private static void runRawCommand(UsbSession usb, String line) throws Exception {
        if (isTlsArming(line)) {
            System.err.println("TLS-arming commands (PROVISION/ENCRYPT/DECRYPT/MANAGE) switch "
                    + "the pipe to opaque TLS. Use APP ENCRYPT/DECRYPT/PEER/INIT, or TerminalBridge "
                    + "for provision.");
            return;
        }
        SeUsbLink link = usb.require();
        link.resetConsole();
        link.transact(line);
    }

    private static byte[] runEncryptFlow(Scanner sc, UsbSession usb, SSLContext ctx) throws Exception {
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
        SeUsbLink link = usb.require();
        try {
            return runEncrypt(link, ctx, pin, message);
        } finally {
            link.resetConsole();
        }
    }

    private static void runDecryptFlow(Scanner sc, UsbSession usb, SSLContext ctx, byte[] lastEncryptReply)
            throws Exception {
        String pin = readPin(sc);
        if (pin == null) {
            return;
        }
        byte[] decryptReplyRaw = readEncryptReplyHex(sc, lastEncryptReply);
        if (decryptReplyRaw == null) {
            return;
        }
        SeUsbLink link = usb.require();
        try {
            runDecrypt(link, ctx, pin, decryptReplyRaw);
        } finally {
            link.resetConsole();
        }
    }

    private static void runOwnerSet(
            Scanner sc, UsbSession usb, Path deviceCert, Path deviceKey, Path saeCa, byte[] ownerSpki
    ) throws Exception {
        String pw = readRequired(sc, "Reset password (8-64 printable ASCII): ");
        if (pw == null) {
            return;
        }
        if (pw.length() < OwnerAuth.PW_MIN || pw.length() > OwnerAuth.PW_MAX) {
            System.err.println("Reset password must be 8–64 characters.");
            return;
        }
        byte[] deviceCertDer = PeerCertHash.loadCert(deviceCert).getEncoded();
        byte[] deviceKeyDer = NodeTls.softwarePrivateKey(deviceKey).getEncoded();
        byte[] saeCaDer = PeerCertHash.loadCert(saeCa).getEncoded();
        SeUsbLink link = usb.require();
        link.resetConsole();
        String begin = link.transact("OWNER SET");
        if (ChipInit.ownerSetRefused(begin)) {
            System.err.println("OWNER SET refused (already enrolled). Use REPLACE.");
            return;
        }
        String done = OwnerAuth.completeOwnerSet(
                link, pw.getBytes(StandardCharsets.US_ASCII), ownerSpki, deviceCertDer, deviceKeyDer, saeCaDer,
                SeUsbLink.CONSOLE_IDLE_MS, SeUsbLink.CONSOLE_SLOW_MAX_MS);
        if (!ChipInit.okLine(done, "owner set ok")) {
            System.err.println("OWNER SET failed.");
        }
    }

    private static void runOwnerReplace(Scanner sc, UsbSession usb, SSLContext ctx, byte[] ownerSpki)
            throws Exception {
        String oldPw = readRequired(sc, "Current reset password: ");
        if (oldPw == null) {
            return;
        }
        String newPw = readRequired(sc, "New reset password (8-64 printable ASCII): ");
        if (newPw == null) {
            return;
        }
        if (newPw.length() < OwnerAuth.PW_MIN || newPw.length() > OwnerAuth.PW_MAX) {
            System.err.println("Reset password must be 8–64 characters.");
            return;
        }
        SeUsbLink link = usb.require();
        OwnerAuth.ManageResult r = OwnerAuth.manage(
                link, ctx, OwnerAuth.CMD_OWNER_REPLACE, null,
                OwnerAuth.ownerReplaceBody(
                        oldPw.getBytes(StandardCharsets.US_ASCII),
                        newPw.getBytes(StandardCharsets.US_ASCII),
                        ownerSpki));
        if (!r.ok()) {
            System.err.println("OWNER REPLACE failed: " + r.msg());
        }
    }

    private static void runPeer(Scanner sc, UsbSession usb, String command, SSLContext ctx) throws Exception {
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
            usb.require().transact("PEER LIST");
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
            SeUsbLink link = usb.require();
            OwnerAuth.ManageResult r = OwnerAuth.manage(
                    link, ctx, OwnerAuth.CMD_PEER_REMOVE, pin, OwnerAuth.peerRemoveBody(name));
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
            SeUsbLink link = usb.require();
            OwnerAuth.ManageResult r = OwnerAuth.manage(
                    link, ctx, OwnerAuth.CMD_PEER_ADD, pin,
                    OwnerAuth.peerAddBody(name, SeBytes.fromHex(hash)));
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

    private static byte[] runEncrypt(SeUsbLink usb, SSLContext ctx, String pin, String message)
            throws Exception {
        usb.armTls("ENCRYPT");
        try (SSLSocket ssl = NodeTls.wrapServer(ctx, usb.asSocket())) {
            ssl.startHandshake();
            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
            ssl.getOutputStream().write(SecureOtp.encodeEncryptRequest(pin, plaintext));
            ssl.getOutputStream().flush();
            try {
                byte[] raw = SecureOtp.readEncryptReply(ssl.getInputStream()).toBytes();
                System.out.println("Encrypt reply (hex): " + SeBytes.toHex(raw));
                return raw;
            } catch (SecureOtp.OtpException e) {
                System.err.println(e.getMessage());
                return null;
            }
        }
    }

    private static void runDecrypt(SeUsbLink usb, SSLContext ctx, String pin, byte[] encryptReply)
            throws Exception {
        usb.armTls("DECRYPT");
        try (SSLSocket ssl = NodeTls.wrapServer(ctx, usb.asSocket())) {
            ssl.startHandshake();
            ssl.getOutputStream().write(SecureOtp.encodeDecryptRequest(pin, encryptReply));
            ssl.getOutputStream().flush();
            try {
                byte[] plaintext = SecureOtp.readDecryptReply(ssl.getInputStream()).plaintext();
                System.out.println("Plaintext: " + new String(plaintext, StandardCharsets.UTF_8));
            } catch (SecureOtp.OtpException e) {
                System.err.println(e.getMessage());
            }
        }
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
            System.out.print("PIN (4-8 digits): ");
            if (!sc.hasNextLine()) {
                return null;
            }
            String pin = sc.nextLine().trim();
            if (PIN.matcher(pin).matches()) {
                return pin;
            }
            System.err.println("PIN must be 4 to 8 decimal digits.");
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

    private static boolean isTlsArming(String line) {
        String first = line.strip().split("\\s+", 2)[0];
        return first.equalsIgnoreCase("PROVISION")
                || first.equalsIgnoreCase("ENCRYPT")
                || first.equalsIgnoreCase("DECRYPT")
                || first.equalsIgnoreCase("MANAGE");
    }

    private static Path pairingKeyPath(Path certsDir, Path deviceCert) {
        String spec = envOrDefault("USERAPP_PAIRING_KEY", "");
        if (!spec.isBlank()) {
            return certPath(certsDir, "USERAPP_PAIRING_KEY", spec);
        }
        Path parent = deviceCert.getParent();
        return (parent == null ? deviceCert : parent).resolve("pairing.key");
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
