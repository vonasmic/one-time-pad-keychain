package fel.cvut.usb;

import fel.cvut.tls.SoftwareTls;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.util.Objects;

/**
 * Arm USB TLS, wrap the CDC streams as a TLS server, then drain leftover
 * console bytes. If the handshake never starts, arm once more. A failure after
 * the handshake is not retried.
 */
public final class SeUsbTls {

    @FunctionalInterface
    public interface Io<T> {
        T run(SSLSocket ssl) throws Exception;
    }

    @FunctionalInterface
    public interface HandshakeSetup {
        void beforeHandshake(SSLSocket ssl) throws Exception;
    }

    private SeUsbTls() {
    }

    public static <T> T run(
            SeUsbLink usb, SSLContext ctx, String verb, boolean needClientAuth, Io<T> io
    ) throws Exception {
        return run(usb, ctx, verb, needClientAuth, null, io);
    }

    public static <T> T run(
            SeUsbLink usb,
            SSLContext ctx,
            String verb,
            boolean needClientAuth,
            HandshakeSetup setup,
            Io<T> io
    ) throws Exception {
        Objects.requireNonNull(usb, "usb");
        Objects.requireNonNull(ctx, "ctx");
        Objects.requireNonNull(verb, "verb");
        Objects.requireNonNull(io, "io");
        Exception last = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            boolean started = false;
            try {
                usb.armTls(verb);
                try (SSLSocket ssl = SoftwareTls.wrapServer(
                        ctx,
                        new StreamSocket(usb.getInputStream(), usb.getOutputStream()),
                        SoftwareTls.TlsProfile.PURE_PQC,
                        needClientAuth)) {
                    if (setup != null) {
                        setup.beforeHandshake(ssl);
                    }
                    ssl.startHandshake();
                    started = true;
                    return io.run(ssl);
                }
            } catch (Exception e) {
                last = e;
                if (started) {
                    throw e;
                }
            } finally {
                usb.resetConsole();
            }
        }
        if (last != null) {
            throw last;
        }
        throw new IllegalStateException("TLS was not attempted");
    }
}
