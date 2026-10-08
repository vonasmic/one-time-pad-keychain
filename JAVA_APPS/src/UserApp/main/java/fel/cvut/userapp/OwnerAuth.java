package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeManage;
import fel.cvut.usb.SeUsbLink;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * USB / TLS adapter over {@link SeManage}. Console commands get plain ASCII
 * (status word or hex); MANAGE gets TLS {@code u8 status | msg}. No demux layer.
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
        String reply = usb.transact("CLIENT CSR", SeUsbLink.CONSOLE_IDLE_MS, SeUsbLink.CONSOLE_SLOW_MAX_MS);
        try {
            return SeBytes.fromHex(reply);
        } catch (RuntimeException e) {
            throw new IOException("failed");
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
