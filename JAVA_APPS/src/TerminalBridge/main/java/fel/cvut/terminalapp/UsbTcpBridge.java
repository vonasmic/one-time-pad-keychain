package fel.cvut.terminalapp;

import fel.cvut.usb.SeUsbLink;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Objects;

/**
 * Dumb USB-serial ↔ TCP byte pipe (socat-like). Arms the device with a console verb, then
 * raw-forwards until either side closes.
 */
public final class UsbTcpBridge {

    private static final long POLL_INTERVAL_MS = 500;
    private static final int TCP_READ_TIMEOUT_MS = 50;
    private static final int USB_CHUNK = 4096;

    private final String serialPortName;
    private final int baudRate;

    public UsbTcpBridge(String serialPortName, int baudRate) {
        this.serialPortName = Objects.requireNonNull(serialPortName, "serialPortName");
        this.baudRate = baudRate;
    }

    /**
     * Open serial, {@link SeUsbLink#armTls(String) arm} with {@code verb}, connect TCP (retry),
     * then raw-relay to {@code host:port}.
     */
    public void sessionArmThenRelay(String host, int port, String verb)
            throws InterruptedException, IOException {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(verb, "verb");
        try (SeUsbLink usb = SeUsbLink.open(serialPortName, baudRate)) {
            usb.armTls(verb);
            oneTcpSession(usb, host, port);
        }
    }

    private static void relay(SeUsbLink usb, Socket socket) throws IOException {
        InputStream tcpIn = socket.getInputStream();
        OutputStream tcpOut = socket.getOutputStream();
        byte[] usbBuf = new byte[USB_CHUNK];
        byte[] tcpBuf = new byte[USB_CHUNK];

        try {
            while (usb.isOpen() && !socket.isClosed() && !Thread.currentThread().isInterrupted()) {
                int n = usb.readRaw(usbBuf, 0, usbBuf.length);
                if (n < 0) {
                    return;
                }
                if (n > 0) {
                    tcpOut.write(usbBuf, 0, n);
                    tcpOut.flush();
                }

                try {
                    int m = tcpIn.read(tcpBuf);
                    if (m < 0) {
                        return;
                    }
                    if (m > 0) {
                        usb.writeTls(tcpBuf, 0, m);
                    }
                } catch (SocketTimeoutException ignored) {
                    // idle
                }
            }
        } finally {
            closeQuietly(socket);
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.shutdownOutput();
        } catch (IOException ignored) {
            /* already half-closed or reset */
        }
        try {
            socket.close();
        } catch (IOException ignored) {
            /* already closed */
        }
    }

    private static void oneTcpSession(SeUsbLink usb, String host, int port)
            throws InterruptedException {
        while (usb.isOpen() && !Thread.currentThread().isInterrupted()) {
            Socket socket;
            try {
                socket = new Socket(host, port);
                socket.setTcpNoDelay(true);
                socket.setSoTimeout(TCP_READ_TIMEOUT_MS);
            } catch (IOException e) {
                Thread.sleep(POLL_INTERVAL_MS);
                continue;
            }
            try (socket) {
                relay(usb, socket);
            } catch (IOException ignored) {
                /* Normal end when the node closes TLS. */
            }
            return;
        }
    }
}
