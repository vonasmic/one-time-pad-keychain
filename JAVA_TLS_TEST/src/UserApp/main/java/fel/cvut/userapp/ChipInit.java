package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.tls.NodeTls;
import fel.cvut.usb.SeUsbLink;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Scanner;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Application-side chip bring-up: unsigned OWNER SET blob, KEYGEN, MANAGE KEM INIT, PAIRING.
 */
final class ChipInit {

    private static final Pattern PIN = Pattern.compile("[0-9]{4,8}");
    private static final Pattern KEY_LINE = Pattern.compile(
            "TROPIC PAIRING KEY ([1-3]) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{64})",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SLOT_LINE = Pattern.compile("slot\\s*=\\s*([1-3])", Pattern.CASE_INSENSITIVE);
    private static final Pattern PRIV_LINE = Pattern.compile("priv\\s*=\\s*([0-9a-fA-F]{64})", Pattern.CASE_INSENSITIVE);
    private static final Pattern PUB_LINE = Pattern.compile("pub\\s*=\\s*([0-9a-fA-F]{64})", Pattern.CASE_INSENSITIVE);

    private ChipInit() {
    }

    static void run(Scanner sc, SeUsbLink usb, Function<Scanner, String> readPin,
                    SSLContext ctx, Path deviceCert, Path deviceKey, Path saeCa, byte[] ownerSpki,
                    Path pairingKey)
            throws Exception {
        boolean restore = pairingKey != null && Files.isRegularFile(pairingKey);
        System.out.println("""
                --- Chip INIT ---
                This will:
                  1. Enroll this UserApp certificate as owner (OWNER SET) if the slot is empty
                     (unsigned USB blob: password + owner SPKI + device cert/key + SAE CA)
                  2. Generate (or PIN-replace over MANAGE TLS) Tropic ECC P-256 slot 0
                  3. Set the ML-KEM PIN over MANAGE TLS (unsigned; owner-pinned, not mTLS)
                  4. Optionally write a new X25519 pairing key (slot 1-3, invalidates
                     factory SH0) or skip with n. If pairing.key exists, n restores it
                     into MCU NV after a reflash (same key, no Tropic write).

                WARNING: losing the PIN loses the ML-KEM seed / pad unwrap.
                WARNING: PAIRING (1-3) is irreversible on real silicon (factory SH0 is burned).
                WARNING: keep pairing.key next to the device cert; MCU reflash without it bricks L3.
                WARNING: replacing an occupied ECC slot destroys the previous identity key.
                WARNING: occupied KEM slot 510 is not overwritten (INIT will stop).
                WARNING: KEM INIT stores the ML-KEM public key in NV (no reflash).
                """);
        if (restore) {
            System.out.println("Found " + pairingKey + " — n restores it (no new Tropic key); 1-3 writes a new one.");
        }

        String resetPw = readResetPassword(sc);
        if (resetPw == null) {
            return;
        }
        String pin = readConfirmedPin(sc, readPin);
        if (pin == null) {
            return;
        }
        String slot = readPairingSlot(sc);
        if (slot == null) {
            return;
        }
        boolean skipPairing = isSkipPairing(slot);
        boolean loadSaved = restore && skipPairing;

        System.out.print("Type YES to continue (anything else cancels): ");
        if (!sc.hasNextLine()) {
            return;
        }
        if (!"YES".equals(sc.nextLine().trim())) {
            System.err.println("INIT cancelled.");
            return;
        }

        byte[] deviceCertDer = derCert(deviceCert);
        byte[] deviceKeyDer = NodeTls.softwarePrivateKey(deviceKey).getEncoded();
        byte[] saeCaDer = derCert(saeCa);

        usb.resetConsole();

        if (loadSaved) {
            PairingBackup backup = PairingBackup.readFile(pairingKey);
            String loadReply = transactSlow(usb, backup.loadCommand());
            if (chipFailed(loadReply) || !okLine(loadReply, "pairing load ok")) {
                System.err.println("INIT stopped at PAIRING LOAD. Delete pairing.key only if this Tropic was never paired.");
                return;
            }
            System.out.println("Restored pairing key from " + pairingKey);
        }

        String ownerBegin = transactSlow(usb, "OWNER SET");
        if (ownerSetRefused(ownerBegin)) {
            System.out.println("Owner already enrolled; skipping OWNER SET.");
        } else {
            String ownerDone = OwnerAuth.completeOwnerSet(
                    usb,
                    resetPw.getBytes(StandardCharsets.US_ASCII),
                    ownerSpki,
                    deviceCertDer,
                    deviceKeyDer,
                    saeCaDer,
                    SeUsbLink.CONSOLE_IDLE_MS,
                    SeUsbLink.CONSOLE_SLOW_MAX_MS);
            if (!okLine(ownerDone, "owner set ok")) {
                System.err.println("INIT stopped at OWNER SET.");
                return;
            }
        }

        String keygen = transactSlow(usb, "TROPIC KEYGEN");
        if (slotOccupied(keygen) || okLine(keygen, "use manage")) {
            System.out.println("ECC slot 0 is occupied. Enter the current PIN to replace it over MANAGE TLS.");
            String current = readPin.apply(sc);
            if (current == null) {
                return;
            }
            OwnerAuth.ManageResult replaced = OwnerAuth.manage(usb, ctx, OwnerAuth.CMD_KEYGEN, current, null);
            if (!replaced.ok()) {
                System.err.println("INIT stopped at KEYGEN: " + replaced.msg());
                return;
            }
        } else if (chipFailed(keygen)) {
            System.err.println("INIT stopped at KEYGEN.");
            return;
        }

        OwnerAuth.ManageResult kem = OwnerAuth.manage(usb, ctx, OwnerAuth.CMD_KEM_INIT, pin, null);
        if (!kem.ok()) {
            System.err.println("INIT stopped at KEM INIT: " + kem.msg());
            return;
        }

        if (skipPairing) {
            if (loadSaved) {
                System.out.println("INIT finished (pairing unchanged; restored from " + pairingKey + ").");
            } else {
                System.out.println("INIT finished (pairing unchanged).");
            }
            return;
        }

        String pairingProbe = transactSlow(usb, "TROPIC PAIRING " + slot);
        if (chipFailed(pairingProbe) || pairingSlotRejected(pairingProbe)) {
            System.err.println("INIT stopped at PAIRING probe.");
            return;
        }

        String pairingConfirm = transactSlow(usb, "TROPIC PAIRING " + slot + " y");
        if (chipFailed(pairingConfirm)) {
            System.err.println("INIT stopped at PAIRING confirm.");
            return;
        }

        PairingBackup created = PairingBackup.parseReply(pairingConfirm);
        if (created == null) {
            System.err.println("PAIRING succeeded on chip but TROPIC PAIRING KEY was missing from the reply.");
            System.err.println("Copy that line now; MCU reflash without pairing.key bricks L3.");
            return;
        }
        try {
            created.save(pairingKey);
            System.out.println("Saved pairing key to " + pairingKey);
        } catch (IOException e) {
            System.err.println("PAIRING succeeded on chip but failed to save " + pairingKey + ": " + e.getMessage());
            System.err.println("Copy the TROPIC PAIRING KEY line now; MCU reflash without it bricks L3.");
        }

        System.out.println("INIT finished.");
    }

    private static byte[] derCert(Path path) throws Exception {
        X509Certificate cert = PeerCertHash.loadCert(path);
        return cert.getEncoded();
    }

    private static String transactSlow(SeUsbLink usb, String command) throws java.io.IOException {
        return usb.transact(command, SeUsbLink.CONSOLE_IDLE_MS, SeUsbLink.CONSOLE_SLOW_MAX_MS);
    }

    private static String readResetPassword(Scanner sc) {
        System.out.print("Reset password (8-64 printable ASCII): ");
        if (!sc.hasNextLine()) {
            return null;
        }
        String pw = sc.nextLine();
        if (pw.length() < OwnerAuth.PW_MIN || pw.length() > OwnerAuth.PW_MAX) {
            System.err.println("Reset password must be 8–64 characters.");
            return null;
        }
        for (int i = 0; i < pw.length(); i++) {
            char c = pw.charAt(i);
            if (c < 0x20 || c > 0x7e) {
                System.err.println("Reset password must be printable ASCII.");
                return null;
            }
        }
        return pw;
    }

    private static String readConfirmedPin(Scanner sc, Function<Scanner, String> readPin) {
        String pin = readPin.apply(sc);
        if (pin == null) {
            return null;
        }
        System.out.print("Confirm PIN: ");
        if (!sc.hasNextLine()) {
            return null;
        }
        String again = sc.nextLine().trim();
        if (!PIN.matcher(again).matches() || !pin.equals(again)) {
            System.err.println("PIN confirmation did not match.");
            return null;
        }
        return pin;
    }

    private static String readPairingSlot(Scanner sc) {
        while (true) {
            System.out.print("Pairing slot to replace SH0 [1-3], or n to skip: ");
            if (!sc.hasNextLine()) {
                return null;
            }
            String choice = parsePairingChoice(sc.nextLine());
            if (choice != null) {
                return choice;
            }
            System.err.println("Enter 1, 2, 3, or n to leave the pairing key unchanged.");
        }
    }

    /** {@code 1}/{@code 2}/{@code 3} to pair, {@code n} to skip; null if invalid. */
    static String parsePairingChoice(String raw) {
        if (raw == null) {
            return null;
        }
        String slot = raw.trim();
        if (slot.equals("1") || slot.equals("2") || slot.equals("3")) {
            return slot;
        }
        if (slot.equalsIgnoreCase("n")) {
            return "n";
        }
        return null;
    }

    static boolean isSkipPairing(String choice) {
        return "n".equalsIgnoreCase(choice);
    }

    static boolean slotOccupied(String reply) {
        return reply != null && reply.toLowerCase(Locale.ROOT).contains("slot occupied");
    }

    static boolean pairingSlotRejected(String reply) {
        if (reply == null) {
            return false;
        }
        String lower = reply.toLowerCase(Locale.ROOT);
        return lower.contains("slot must be") || lower.contains("bad tropic pairing");
    }

    static boolean ownerSetRefused(String reply) {
        if (reply == null) {
            return false;
        }
        String lower = reply.toLowerCase(Locale.ROOT);
        return lower.contains("owner set refused") || lower.contains("already enrolled");
    }

    static boolean okLine(String reply, String token) {
        return reply != null && reply.toLowerCase(Locale.ROOT).contains(token);
    }

    static boolean chipFailed(String reply) {
        if (reply == null || reply.isBlank()) {
            return true;
        }
        String lower = reply.toLowerCase(Locale.ROOT);
        return lower.contains("command failed")
                || lower.contains("pin mismatch")
                || lower.contains("bad tropic")
                || lower.contains("bad peer")
                || lower.contains("device_tampered")
                || lower.contains("not ready")
                || lower.contains("unknown command")
                || lower.contains("unknown tropic")
                || lower.contains("unknown peer");
    }

    record PairingBackup(int slot, byte[] priv, byte[] pub) {
        PairingBackup {
            if (slot < 1 || slot > 3) {
                throw new IllegalArgumentException("pairing slot must be 1-3");
            }
            if (priv == null || priv.length != 32 || pub == null || pub.length != 32) {
                throw new IllegalArgumentException("pairing keys must be 32 bytes");
            }
        }

        String loadCommand() {
            return "TROPIC PAIRING LOAD " + slot + " " + SeBytes.toHex(priv) + " " + SeBytes.toHex(pub);
        }

        void save(Path path) throws IOException {
            Path parent = path.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            String body = "slot=" + slot + "\npriv=" + SeBytes.toHex(priv) + "\npub=" + SeBytes.toHex(pub) + "\n";
            Files.writeString(path, body);
        }

        static PairingBackup parseReply(String reply) {
            if (reply == null || reply.isBlank()) {
                return null;
            }
            for (String line : reply.split("\\R")) {
                Matcher m = KEY_LINE.matcher(line.strip());
                if (m.matches()) {
                    return new PairingBackup(
                            Integer.parseInt(m.group(1)),
                            SeBytes.fromHex(m.group(2)),
                            SeBytes.fromHex(m.group(3)));
                }
            }
            return null;
        }

        static PairingBackup readFile(Path path) throws IOException {
            String slotHex = null;
            String privHex = null;
            String pubHex = null;
            for (String raw : Files.readAllLines(path)) {
                String line = raw.strip();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                Matcher slot = SLOT_LINE.matcher(line);
                if (slot.matches()) {
                    slotHex = slot.group(1);
                    continue;
                }
                Matcher priv = PRIV_LINE.matcher(line);
                if (priv.matches()) {
                    privHex = priv.group(1);
                    continue;
                }
                Matcher pub = PUB_LINE.matcher(line);
                if (pub.matches()) {
                    pubHex = pub.group(1);
                }
            }
            if (slotHex == null || privHex == null || pubHex == null) {
                throw new IOException(path + " must contain slot=, priv=, and pub= (64 hex each)");
            }
            return new PairingBackup(Integer.parseInt(slotHex), SeBytes.fromHex(privHex), SeBytes.fromHex(pubHex));
        }
    }
}
