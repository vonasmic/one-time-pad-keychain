package fel.cvut.userapp;

import fel.cvut.se.SeManage;
import fel.cvut.se.SeUsbDump;
import fel.cvut.usb.SeUsbLink;
import fel.cvut.usb.SeUsbTls;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

/**
 * USB / TLS adapter over {@link SeManage}. OWNER SET is unsigned USB dumps;
 * MANAGE is owner-pinned TLS (no device client cert).
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
        SeUsbDump begin = usb.transactDump("OWNER SET");
        if (begin.refused()) {
            return new ChipInit.OwnerSetResult.AlreadyEnrolled();
        }
        if (!begin.ok()) {
            return new ChipInit.OwnerSetResult.Failed("failed");
        }
        usb.writeRaw(SeManage.encodeOwnerSet(password, spki, saeCa));
        SeUsbDump done = usb.readDump(SeUsbLink.CONSOLE_SLOW_MAX_MS);
        return classifyOwnerSetDone(done);
    }

    @Override
    public Optional<byte[]> tropicPub() throws Exception {
        SeUsbDump dump = usb.transactDump("TROPIC PUB");
        if (dump.empty()) {
            return Optional.empty();
        }
        byte[] xy = dump.tropicPub();
        if (xy == null) {
            throw new IOException("failed");
        }
        return Optional.of(xy);
    }

    @Override
    public Optional<byte[]> tropicKemPub() throws Exception {
        SeUsbDump dump = usb.transactDump("TROPIC KEM PUB");
        if (dump.empty()) {
            return Optional.empty();
        }
        byte[] pk = dump.kemPub();
        if (pk == null) {
            throw new IOException("failed");
        }
        return Optional.of(pk);
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
        byte[] pub = usb.transactDump("CLIENT CSR").clientCsr();
        if (pub == null) {
            throw new IOException("failed");
        }
        return pub;
    }

    @Override
    public Optional<byte[]> clientHash() throws Exception {
        byte[] hash = usb.transactDump("CLIENT HASH").clientHash();
        return Optional.ofNullable(hash);
    }

    static ChipInit.OwnerSetResult classifyOwnerSetDone(SeUsbDump dump) {
        if (dump == null) {
            return new ChipInit.OwnerSetResult.Failed("failed");
        }
        if (dump.refused()) {
            return new ChipInit.OwnerSetResult.AlreadyEnrolled();
        }
        if (dump.ok()) {
            return new ChipInit.OwnerSetResult.Ok();
        }
        return new ChipInit.OwnerSetResult.Failed("failed");
    }
}
