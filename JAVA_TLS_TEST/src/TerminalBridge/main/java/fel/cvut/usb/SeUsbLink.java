package fel.cvut.usb;

import com.fazecast.jSerialComm.SerialPort;
import com.fazecast.jSerialComm.SerialPortInvalidPortException;
import com.fazecast.jSerialComm.SerialPortTimeoutException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import fel.cvut.se.SeUsbDump;

import java.util.Objects;

/**
 * USB CDC ACM serial adapter: ASCII ({@link #transact} / {@link #readConsole}),
 * typed {@link #readDump} frames, then TLS via {@link UsbCdcRxMachine}. Dump
 * bodies may contain {@code 0x16}; length prefix wins over ClientHello.
 *
 * <p>After application data, {@link javax.net.ssl.SSLSocket#close()} sends
 * {@code close_notify}. The chip stays in TLS until that alert (and its own)
 * complete, then {@link #resetConsole} drains back to ASCII.
 *
 * <p>Serial path is {@code USB_SERIAL_PORT}. SAE host/ports are the process
 * {@code NODE_HOSTNAME} / {@code NODE_NATIVE_PORT} / {@code NODE_TERMINAL_PORT}.
 */
public final class SeUsbLink implements AutoCloseable {

    public static final String DEFAULT_PORT = "/dev/ttyACM0";
    public static final int DEFAULT_BAUD = 115200;
    /**
     * Firmware {@code TLS_CMD_MAX}: short ASCII command plus unix time.
     */
    public static final int MAX_COMMAND_CHARS = 160;
    /** Quiet window after the last console byte before {@link #readConsole} returns. */
    public static final long CONSOLE_IDLE_MS = 300;
    /** Default overall wait for HELP / PEER and other short console replies. */
    public static final long CONSOLE_MAX_MS = 3_000;
    /** Overall wait for KEYGEN / KEM INIT / PAIRING (Tropic SPI). */
    public static final long CONSOLE_SLOW_MAX_MS = 30_000;
    /** Wait after {@link #armTls} for ClientHello, or a firmware TLS-arm refusal. */
    public static final long TLS_ARM_MAX_MS = 15_000;

    private static final long POLL_INTERVAL_MS = 500;
    private static final int SERIAL_READ_TIMEOUT_MS = 50;
    private static final int USB_CHUNK = 4096;
    private static final long RESET_DRAIN_IDLE_MS = 150;
    private static final long RESET_DRAIN_MAX_MS = 1_000;

    private final String serialPortName;
    private final SerialPort serial;
    private final InputStream serialIn;
    private final OutputStream serialOut;
    private final InputStream tlsIn;
    private final OutputStream tlsOut;
    private final UsbCdcRxMachine rx = new UsbCdcRxMachine();

    private final byte[] scratch = new byte[USB_CHUNK];
    private volatile boolean closed;

    private SeUsbLink(String serialPortName, SerialPort serial) {
        this.serialPortName = serialPortName;
        this.serial = serial;
        this.serialIn = serial.getInputStream();
        this.serialOut = serial.getOutputStream();
        this.tlsIn = new TlsInputStream();
        this.tlsOut = new TlsOutputStream();
    }

    public static SeUsbLink open(String serialPortName, int baudRate) throws InterruptedException {
        Objects.requireNonNull(serialPortName, "serialPortName");
        SerialPort serial = openWhenPresent(serialPortName, baudRate);
        System.out.println("[usb] Opened " + serialPortName + " @ " + baudRate);
        return new SeUsbLink(serialPortName, serial);
    }

    public synchronized void sendCommand(String command) throws IOException {
        Objects.requireNonNull(command, "command");
        String trimmed = command.strip();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("command must not be empty");
        }
        if (trimmed.length() > MAX_COMMAND_CHARS) {
            throw new IllegalArgumentException("command longer than " + MAX_COMMAND_CHARS + " chars");
        }
        ensureOpen();
        rx.reset();
        String line = trimmed.endsWith("\n") ? trimmed : trimmed + "\n";
        try {
            serialOut.write(line.getBytes(StandardCharsets.US_ASCII));
            serialOut.flush();
        } catch (IOException e) {
            markSerialGone();
            throw e;
        }
        System.out.println("[usb] Sent " + trimmed);
    }

    /**
     * Write opaque bytes on the CDC (unsigned OWNER SET blob). Does not switch the TLS path.
     */
    public synchronized void writeRaw(byte[] data) throws IOException {
        Objects.requireNonNull(data, "data");
        ensureOpen();
        rx.disarmTls();
        try {
            serialOut.write(data);
            serialOut.flush();
        } catch (IOException e) {
            markSerialGone();
            throw e;
        }
    }

    /**
     * Arm ENCRYPT/DECRYPT/MANAGE/PROVISION and wait until the chip sends ClientHello.
     * Firmware refusals ({@code failed}) throw instead of leaving
     * {@link javax.net.ssl.SSLSocket#startHandshake()} blocked forever.
     */
    public void armTls(String verb) throws IOException {
        Objects.requireNonNull(verb, "verb");
        sendCommand(verb.strip() + " " + Instant.now().getEpochSecond());
        awaitTlsOrThrow(TLS_ARM_MAX_MS);
    }

    /**
     * Pump CDC until ClientHello ({@code 0x16}) or ASCII {@code failed}.
     * Leaves hello bytes in leftover for the next {@link #readTls}.
     */
    public synchronized void awaitTlsOrThrow(long maxMs) throws IOException {
        if (maxMs < 0) {
            throw new IllegalArgumentException("maxMs must be >= 0");
        }
        ensureOpen();
        throwIfTlsArmFailed();
        long start = System.currentTimeMillis();
        while (!rx.isTlsActive()) {
            throwIfTlsArmFailed();
            if (System.currentTimeMillis() - start >= maxMs) {
                throw new IOException("TLS start timed out");
            }
            if (rx.pending() > 0) {
                int pending = rx.pending();
                rx.takeTls(scratch, 0, 0);
                throwIfTlsArmFailed();
                if (rx.isTlsActive()) {
                    return;
                }
                if (rx.pending() < pending) {
                    continue;
                }
            }
            int n;
            try {
                n = serialIn.read(scratch);
            } catch (SerialPortTimeoutException e) {
                continue;
            } catch (IOException e) {
                System.out.println("[usb] Serial closed");
                markSerialGone();
                throw e;
            }
            if (n < 0) {
                System.out.println("[usb] Serial closed");
                markSerialGone();
                throw new IOException("USB serial is closed");
            }
            if (n > 0) {
                rx.feed(scratch, 0, n);
            }
        }
    }

    /**
     * Drain CDC RX so the next {@link #transact} sees ASCII console.
     * Call after {@link javax.net.ssl.SSLSocket#close()} so {@code close_notify}
     * has already been exchanged.
     */
    public synchronized void resetConsole() {
        rx.reset();
        if (!isOpen()) {
            return;
        }
        long start = System.currentTimeMillis();
        long last = start;
        while (System.currentTimeMillis() - start < RESET_DRAIN_MAX_MS) {
            if (System.currentTimeMillis() - last >= RESET_DRAIN_IDLE_MS) {
                return;
            }
            int n;
            try {
                n = serialIn.read(scratch);
            } catch (SerialPortTimeoutException e) {
                continue;
            } catch (IOException e) {
                return;
            }
            if (n < 0) {
                return;
            }
            if (n > 0) {
                last = System.currentTimeMillis();
            }
        }
    }

    /**
     * Read ASCII console until {@code idleMs} of silence after the first byte, or {@code maxMs} total.
     * Dump frames are skipped. Does not treat {@code 0x16} as TLS.
     */
    public synchronized String readConsole(long idleMs, long maxMs) throws IOException {
        if (idleMs < 0 || maxMs < 0) {
            throw new IllegalArgumentException("idleMs and maxMs must be >= 0");
        }
        ensureOpen();
        rx.disarmTls();
        StringBuilder out = new StringBuilder();
        StringBuilder line = new StringBuilder();
        long start = System.currentTimeMillis();
        long lastByteAt = 0L;
        byte[] pending = rx.takePendingRaw();
        if (pending.length > 0) {
            lastByteAt = start;
            appendConsoleBytes(pending, 0, pending.length, line, out);
        }
        while (true) {
            long now = System.currentTimeMillis();
            if (now - start >= maxMs) {
                break;
            }
            if (lastByteAt > 0L && now - lastByteAt >= idleMs) {
                break;
            }
            if (Thread.currentThread().isInterrupted()) {
                throw new IOException("Interrupted while reading USB console");
            }
            int n;
            try {
                n = serialIn.read(scratch);
            } catch (SerialPortTimeoutException e) {
                continue;
            } catch (IOException e) {
                System.out.println("[usb] Serial closed");
                markSerialGone();
                throw e;
            }
            if (n < 0) {
                System.out.println("[usb] Serial closed");
                markSerialGone();
                throw new IOException("USB serial is closed");
            }
            if (n == 0) {
                continue;
            }
            lastByteAt = System.currentTimeMillis();
            appendConsoleBytes(scratch, 0, n, line, out);
        }
        if (!line.isEmpty()) {
            emitConsoleLine(line.toString(), out);
        }
        return out.toString();
    }

    public synchronized String transact(String command) throws IOException {
        return transact(command, CONSOLE_IDLE_MS, CONSOLE_MAX_MS);
    }

    public synchronized String transact(String command, long idleMs, long maxMs) throws IOException {
        sendCommand(command);
        return readConsole(idleMs, maxMs);
    }

    public synchronized SeUsbDump transactDump(String command) throws IOException {
        return transactDump(command, CONSOLE_SLOW_MAX_MS);
    }

    /**
     * Send an ASCII command and wait for one {@code 0xB1} dump (PUB / CSR / HASH / OTP LEFT / PEER LIST / OWNER SET).
     */
    public synchronized SeUsbDump transactDump(String command, long maxMs) throws IOException {
        sendCommand(command);
        return readDump(maxMs);
    }

    /**
     * Wait for one dump frame. ASCII {@code failed} throws. Timeout throws.
     */
    public synchronized SeUsbDump readDump(long maxMs) throws IOException {
        if (maxMs < 0) {
            throw new IllegalArgumentException("maxMs must be >= 0");
        }
        ensureOpen();
        rx.disarmTls();
        throwIfTlsArmFailed();
        long start = System.currentTimeMillis();
        SeUsbDump dump = rx.takeDump();
        if (dump != null) {
            return dump;
        }
        while (System.currentTimeMillis() - start < maxMs) {
            throwIfTlsArmFailed();
            int n;
            try {
                n = serialIn.read(scratch);
            } catch (SerialPortTimeoutException e) {
                dump = rx.takeDump();
                if (dump != null) {
                    return dump;
                }
                continue;
            } catch (IOException e) {
                System.out.println("[usb] Serial closed");
                markSerialGone();
                throw e;
            }
            if (n < 0) {
                System.out.println("[usb] Serial closed");
                markSerialGone();
                throw new IOException("USB serial is closed");
            }
            if (n > 0) {
                rx.feed(scratch, 0, n);
            }
            dump = rx.takeDump();
            if (dump != null) {
                return dump;
            }
        }
        throwIfTlsArmFailed();
        throw new IOException("failed");
    }

    /**
     * One serial poll. Returns TLS bytes only (0 on idle / dump, -1 if the port closed).
     */
    public synchronized int readTls(byte[] dest, int off, int len) throws IOException {
        Objects.requireNonNull(dest, "dest");
        if (off < 0 || len < 0 || off + len > dest.length) {
            throw new IndexOutOfBoundsException();
        }
        if (len == 0) {
            return 0;
        }
        if (!isOpen()) {
            return -1;
        }
        throwIfTlsArmFailed();
        if (rx.isTlsActive()) {
            int fromLeftover = rx.takeTls(dest, off, len);
            if (fromLeftover > 0) {
                return fromLeftover;
            }
        } else if (rx.pending() > 0) {
            int fromFrame = rx.takeTls(dest, off, len);
            throwIfTlsArmFailed();
            if (fromFrame != 0) {
                return fromFrame;
            }
        }
        int n;
        try {
            n = serialIn.read(scratch);
        } catch (SerialPortTimeoutException e) {
            return 0;
        } catch (IOException e) {
            System.out.println("[usb] Serial closed");
            markSerialGone();
            return -1;
        }
        if (n < 0) {
            System.out.println("[usb] Serial closed");
            markSerialGone();
            return -1;
        }
        if (n == 0) {
            return 0;
        }
        rx.feed(scratch, 0, n);
        int fromFrame = rx.takeTls(dest, off, len);
        throwIfTlsArmFailed();
        return fromFrame;
    }

    public synchronized void writeTls(byte[] src, int off, int len) throws IOException {
        Objects.requireNonNull(src, "src");
        ensureOpen();
        try {
            serialOut.write(src, off, len);
            serialOut.flush();
        } catch (IOException e) {
            markSerialGone();
            throw e;
        }
    }

    public InputStream getInputStream() {
        return tlsIn;
    }

    public OutputStream getOutputStream() {
        return tlsOut;
    }

    public Socket asSocket() {
        return new StreamSocket(tlsIn, tlsOut);
    }

    public boolean isOpen() {
        if (closed) {
            return false;
        }
        if (!serial.isOpen() || !Files.exists(Path.of(serialPortName))) {
            System.out.println("[usb] Serial closed");
            markSerialGone();
            return false;
        }
        return true;
    }

    public String serialPortName() {
        return serialPortName;
    }

    @Override
    public void close() {
        closed = true;
        serial.closePort();
    }

    private void markSerialGone() {
        closed = true;
        serial.closePort();
    }

    private void ensureOpen() throws IOException {
        if (!isOpen()) {
            throw new IOException("USB serial is closed");
        }
    }

    private void throwIfTlsArmFailed() throws IOException {
        String msg = rx.consumeArmFailure();
        if (msg == null) {
            return;
        }
        throw new IOException("failed");
    }

    private static void appendConsoleBytes(
            byte[] src, int off, int len, StringBuilder line, StringBuilder out) {
        for (int i = 0; i < len; i++) {
            char c = (char) (src[off + i] & 0xFF);
            if (c == '\r') {
                continue;
            }
            if (c == '\n') {
                emitConsoleLine(line.toString(), out);
                line.setLength(0);
            } else {
                line.append(c);
            }
        }
    }

    private static void emitConsoleLine(String raw, StringBuilder out) {
        String line = raw.strip();
        if (line.isEmpty()) {
            return;
        }
        System.out.println(line);
        if (!out.isEmpty()) {
            out.append('\n');
        }
        out.append(line);
    }

    private static SerialPort openWhenPresent(String serialPortName, int baudRate)
            throws InterruptedException {
        boolean waitingLogged = false;
        while (!Thread.currentThread().isInterrupted()) {
            if (!Files.exists(Path.of(serialPortName))) {
                if (!waitingLogged) {
                    System.out.println("[usb] Waiting for " + serialPortName + " ...");
                    waitingLogged = true;
                }
                Thread.sleep(POLL_INTERVAL_MS);
                continue;
            }
            try {
                SerialPort serial = SerialPort.getCommPort(serialPortName);
                serial.setComPortParameters(baudRate, 8, SerialPort.ONE_STOP_BIT, SerialPort.NO_PARITY);
                /* BLOCKING so idle/maxMs work when the chip sends nothing.
                 * SEMI_BLOCKING waits forever for the first byte. */
                serial.setComPortTimeouts(
                        SerialPort.TIMEOUT_READ_BLOCKING | SerialPort.TIMEOUT_WRITE_BLOCKING,
                        SERIAL_READ_TIMEOUT_MS,
                        500);
                if (!serial.openPort()) {
                    Thread.sleep(POLL_INTERVAL_MS);
                    continue;
                }
                serial.setDTR();
                serial.setRTS();
                return serial;
            } catch (SerialPortInvalidPortException e) {
                if (!waitingLogged) {
                    System.out.println("[usb] Waiting for " + serialPortName + " ...");
                    waitingLogged = true;
                }
                Thread.sleep(POLL_INTERVAL_MS);
            }
        }
        throw new InterruptedException("Interrupted while waiting for " + serialPortName);
    }

    private final class TlsInputStream extends InputStream {
        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xFF);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            while (!closed && isOpen() && !Thread.currentThread().isInterrupted()) {
                int n = readTls(b, off, len);
                if (n != 0) {
                    return n;
                }
            }
            return -1;
        }

        @Override
        public int available() {
            return rx.pending();
        }

        @Override
        public void close() {
            /* Owner is SeUsbLink; SSLSocket teardown must not unplug CDC. */
        }
    }

    private final class TlsOutputStream extends OutputStream {
        @Override
        public void write(int b) throws IOException {
            writeTls(new byte[] {(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            writeTls(b, off, len);
        }

        @Override
        public void close() {
            /* Owner is SeUsbLink; SSLSocket teardown must not unplug CDC. */
        }
    }
}
