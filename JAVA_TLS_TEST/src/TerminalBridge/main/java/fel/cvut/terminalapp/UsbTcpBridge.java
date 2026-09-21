package fel.cvut.terminalapp;

import fel.cvut.usb.SeUsbLink;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * USB-serial ↔ TCP relay for provision: arm the device, then copy TLS bytes to the SAE.
 *
 * <p>USB open and ASCII commands live in {@link SeUsbLink}. Dump vs ClientHello
 * filtering lives in {@link fel.cvut.usb.UsbCdcRxMachine}. Serial path and SAE host/port
 * are constructor / {@link #run} arguments from the process environment.
 */
public final class UsbTcpBridge {

    public static final String DEFAULT_PORT = SeUsbLink.DEFAULT_PORT;

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
     * Open serial, arm the device, open TCP after ClientHello, relay until either side closes.
     * Runs once; use {@link #run(String, int, Supplier, BooleanSupplier)} to offer another session.
     */
    public void run(String host, int port, Supplier<String> preTlsCommand) {
        run(host, port, preTlsCommand, () -> false);
    }

    /**
     * Like {@link #run(String, int, Supplier)} but asks {@code restartPrompt} after each session.
     */
    public void run(String host, int port, Supplier<String> preTlsCommand, BooleanSupplier restartPrompt) {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(preTlsCommand, "preTlsCommand");
        Objects.requireNonNull(restartPrompt, "restartPrompt");
        if (Thread.currentThread().isInterrupted()) {
            return;
        }
        try {
            do {
                try (SeUsbLink usb = SeUsbLink.open(serialPortName, baudRate)) {
                    oneTcpSession(usb, host, port, preTlsCommand.get());
                }
            } while (!Thread.currentThread().isInterrupted() && restartPrompt.getAsBoolean());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * One serial open + one TCP connect (retried) + command + relay.
     */
    public void session(String host, int port, String preTlsCommand) throws InterruptedException {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(preTlsCommand, "preTlsCommand");
        try (SeUsbLink usb = SeUsbLink.open(serialPortName, baudRate)) {
            oneTcpSession(usb, host, port, preTlsCommand);
        }
    }

    /**
     * Copy TLS bytes between an already-armed {@link SeUsbLink} and {@code socket}.
     */
    public static void relayTls(SeUsbLink usb, Socket socket) throws IOException {
        Objects.requireNonNull(usb, "usb");
        Objects.requireNonNull(socket, "socket");
        InputStream tcpIn = socket.getInputStream();
        OutputStream tcpOut = socket.getOutputStream();
        byte[] usbBuf = new byte[USB_CHUNK];
        byte[] tcpBuf = new byte[USB_CHUNK];

        try {
            while (usb.isOpen() && !socket.isClosed() && !Thread.currentThread().isInterrupted()) {
                int n = usb.readTls(usbBuf, 0, usbBuf.length);
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
                    // idle, like select() timeout
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

    private static void oneTcpSession(
            SeUsbLink usb, String host, int port, String preTlsCommand
    ) throws InterruptedException {
        byte[] first = new byte[USB_CHUNK];
        int n;
        try {
            usb.sendCommand(preTlsCommand);
            usb.awaitTlsOrThrow(SeUsbLink.TLS_ARM_MAX_MS);
            n = usb.readTls(first, 0, first.length);
        } catch (IOException e) {
            System.err.println("TLS arm failed: " + e.getMessage());
            return;
        }
        if (n <= 0) {
            return;
        }

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
                socket.getOutputStream().write(first, 0, n);
                socket.getOutputStream().flush();
                relayTls(usb, socket);
            } catch (IOException ignored) {
                /* Normal end of provision session when the node closes TLS. */
            }
            return;
        }
    }
}
