package fel.cvut.userapp;

import fel.cvut.tls.SoftwareTls;
import fel.cvut.usb.SeUsbLink;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.util.Objects;

/**
 * Arm USB TLS, wrap the CDC streams as a TLS server, then drain back to ASCII.
 */
final class SeUsbTls {

    @FunctionalInterface
    interface Io<T> {
        T run(SSLSocket ssl) throws Exception;
    }

    private SeUsbTls() {
    }

    static <T> T run(
            SeUsbLink usb, SSLContext ctx, String verb, boolean needClientAuth, Io<T> io
    ) throws Exception {
        Objects.requireNonNull(usb, "usb");
        Objects.requireNonNull(ctx, "ctx");
        Objects.requireNonNull(verb, "verb");
        Objects.requireNonNull(io, "io");
        try {
            usb.armTls(verb);
            try (SSLSocket ssl = SoftwareTls.wrapServer(
                    ctx,
                    new StreamSocket(usb.getInputStream(), usb.getOutputStream()),
                    SoftwareTls.TlsProfile.PURE_PQC,
                    needClientAuth)) {
                ssl.startHandshake();
                return io.run(ssl);
            }
        } finally {
            usb.resetConsole();
        }
    }
}
