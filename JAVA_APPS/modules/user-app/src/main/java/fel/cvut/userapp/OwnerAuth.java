package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeManage;
import fel.cvut.usb.SeUsbLink;
import fel.cvut.usb.SeUsbTls;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * USB / TLS adapter over {@link SeManage}. Console commands (including OWNER SET
 * begin and apply status) are type {@code 0x00}; the OWNER SET blob and MANAGE TLS
 * are type {@code 0x01}.
 */
final class OwnerAuth implements ChipInit.ChipPort {

    private final SeUsbLink usb;
    private final SSLContext ctx;

    OwnerAuth(SeUsbLink usb, SSLContext ctx) {
        this.usb = Objects.requireNonNull(usb, "usb");
        this.ctx = Objects.requireNonNull(ctx, "ctx");
    }

    @Override
    public ChipInit.OwnerSetResult ownerSet(byte[] password, byte[] spki, byte[] saeCa)
            throws Exception {
        return ownerSet(usb, password, spki, saeCa);
    }

    static ChipInit.OwnerSetResult ownerSet(SeUsbLink usb, byte[] password, byte[] spki, byte[] saeCa)
            throws IOException {
        Objects.requireNonNull(usb, "usb");
        usb.resetConsole();
        String begin = asciiWord(usb.transact("OWNER SET"));
        if ("refused".equals(begin)) {
            return new ChipInit.OwnerSetResult.AlreadyEnrolled();
        }
        if (!"ok".equals(begin)) {
            return new ChipInit.OwnerSetResult.Failed("failed");
        }
        usb.writeRaw(SeManage.encodeOwnerSet(password, spki, saeCa));
        /* Apply status is se_usb_debug_puts: type 0x00, not a Secure span. */
        String done = usb.readConsole(SeUsbLink.CONSOLE_IDLE_MS, SeUsbLink.CONSOLE_SLOW_MAX_MS);
        return classifyOwnerSetDone(done);
    }

    @Override
    public Optional<byte[]> tropicPub() throws Exception {
        return asciiHexOrEmpty(usb.transact("TROPIC PUB"));
    }

    @Override
    public Optional<byte[]> tropicKemPub() throws Exception {
        return asciiHexOrEmpty(usb.transact("TROPIC KEM PUB"));
    }

    @Override
    public SeManage.Reply manage(int cmd, String pin, byte[] body) throws Exception {
        return manage(usb, ctx, cmd, pin, body);
    }

    /**
     * Owner-pinned TLS (no device client cert). Streams one unsigned command, then reads
     * {@code u8 status | u16le msg_len | msg}.
     */
    static SeManage.Reply manage(SeUsbLink usb, SSLContext ctx, int cmd, String pin, byte[] body)
            throws Exception {
        Objects.requireNonNull(usb, "usb");
        Objects.requireNonNull(ctx, "ctx");
        byte[] pinB = (pin == null || pin.isEmpty()) ? new byte[0] : SeManage.pinBytes(pin);
        return SeUsbTls.run(usb, ctx, "MANAGE", false, ssl -> {
            ssl.getOutputStream().write(SeManage.encodeRequest(cmd, pinB, body));
            ssl.getOutputStream().flush();
            return SeManage.readReply(ssl.getInputStream());
        });
    }

    @Override
    public byte[] clientCsrPub() throws Exception {
        usb.sendCommand("CLIENT CSR");
        StringBuilder acc = new StringBuilder();
        long deadline = System.currentTimeMillis() + SeUsbLink.CONSOLE_SLOW_MAX_MS;
        boolean first = true;
        while (true) {
            long left = deadline - System.currentTimeMillis();
            if (left <= 0L) {
                break;
            }
            long idle = first ? SeUsbLink.CONSOLE_IDLE_MS : SeUsbLink.CONSOLE_HEX_IDLE_MS;
            long max = first ? left : Math.min(left, SeUsbLink.CONSOLE_HEX_IDLE_MS);
            first = false;
            String chunk = usb.readConsole(idle, max);
            if (chunk == null || chunk.isBlank()) {
                break;
            }
            if (!acc.isEmpty()) {
                acc.append('\n');
            }
            acc.append(chunk);
            String word = asciiWord(acc.toString());
            if ("failed".equals(word) || "empty".equals(word)) {
                throw new IOException("failed");
            }
            byte[] pub = csrPubOrNull(acc.toString());
            if (pub != null && pub.length == SeConstants.MLDSA_PUB_LEN) {
                return pub;
            }
        }
        byte[] pub = csrPubOrNull(acc.toString());
        if (pub == null) {
            throw new IOException("failed");
        }
        if (pub.length != SeConstants.MLDSA_PUB_LEN) {
            throw new IOException("CLIENT CSR truncated (" + pub.length + " of "
                    + SeConstants.MLDSA_PUB_LEN + " bytes)");
        }
        return pub;
    }

    /** Public key bytes, or null when the console reply is empty, failed, or not hex. */
    static byte[] csrPubOrNull(String reply) {
        if (reply == null || reply.isBlank()) {
            return null;
        }
        String word = asciiWord(reply);
        if (word.isEmpty() || "failed".equals(word) || "empty".equals(word)) {
            return null;
        }
        try {
            byte[] pub = SeBytes.fromHex(reply);
            return pub.length == 0 ? null : pub;
        } catch (RuntimeException e) {
            return null;
        }
    }

    @Override
    public Optional<byte[]> clientHash() throws Exception {
        return asciiHexOrEmpty(usb.transact("CLIENT HASH"));
    }

    static ChipInit.OwnerSetResult classifyOwnerSetDone(String reply) {
        String word = asciiWord(reply);
        return switch (word) {
            case "ok" -> new ChipInit.OwnerSetResult.Ok();
            case "refused" -> new ChipInit.OwnerSetResult.AlreadyEnrolled();
            case "" -> new ChipInit.OwnerSetResult.Failed("failed");
            default -> new ChipInit.OwnerSetResult.Failed(word);
        };
    }

    /** First non-blank ASCII line, lowercased (console status words). */
    private static String asciiWord(String reply) {
        if (reply == null || reply.isBlank()) {
            return "";
        }
        return reply.strip().lines()
                .map(String::strip)
                .filter(s -> !s.isEmpty())
                .findFirst()
                .orElse("")
                .toLowerCase(Locale.ROOT);
    }

    /** Console hex body, or empty occupancy / missing. */
    private static Optional<byte[]> asciiHexOrEmpty(String reply) throws IOException {
        String word = asciiWord(reply);
        if (word.isEmpty() || "empty".equals(word) || "failed".equals(word)) {
            if ("failed".equals(word)) {
                throw new IOException("failed");
            }
            return Optional.empty();
        }
        try {
            return Optional.of(SeBytes.fromHex(reply));
        } catch (RuntimeException e) {
            throw new IOException("failed");
        }
    }
}
