package fel.cvut.usb;

import com.fazecast.jSerialComm.SerialPort;
import com.fazecast.jSerialComm.SerialPortInvalidPortException;
import com.fazecast.jSerialComm.SerialPortTimeoutException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * USB CDC ACM adapter. Every read and write is an {@link UsbFrame}: type
 * {@code 0x00} is the console, type {@code 0x01} is a Secure payload (TLS or
 * the OWNER SET blob). {@link #transact} / {@link #readConsole} use command
 * frames. {@link #armTls} then {@link #getInputStream()} / {@link #getOutputStream()}
 * carry Secure frames into {@link javax.net.ssl.SSLSocket}.
 *
 * <p>Serial path is {@code USB_SERIAL_PORT}. {@code auto} (the default) scans for the
 * keychain CDC device instead of a fixed {@code /dev/ttyACM*} node. An explicit path
 * is opened as given. SaeNode and UserApp open this link themselves; there is
 * no USB-to-TCP relay.
 *
 * <p>A dedicated reader thread always drains the tty. Provision's server flight is
 * large enough that a CDC write blocks inside {@code tcdrain} until the board
 * reads it, and the board cannot finish that read until the host accepts the
 * device certificate. MANAGE has no device certificate, and a PTY write does not
 * block this way, so only hardware provision used to stall in {@code WANT_READ}.
 */
public final class SeUsbLink implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(SeUsbLink.class.getName());

    /** Scan for the board. {@code scan} is the same token. */
    public static final String DEFAULT_PORT = "auto";

    public static boolean isAutoPort(String name) {
        return CdcPortScan.isAuto(name);
    }
    public static final int DEFAULT_BAUD = 115200;
    /**
     * Firmware {@code TLS_CMD_MAX}: short ASCII command plus unix time.
     */
    public static final int MAX_COMMAND_CHARS = 160;
    /** Quiet window after the last console byte before {@link #readConsole} returns. */
    public static final long CONSOLE_IDLE_MS = 300;
    /**
     * Extra quiet window while a multi-frame hex dump is still short of its
     * expected length. Secure leftover ({@code 0x01}) does not feed the console
     * buffer, so a 300 ms console idle during TLS drain looks like a truncated
     * CLIENT CSR.
     */
    public static final long CONSOLE_HEX_IDLE_MS = 1_500;
    /** Default overall wait for HELP / PEER and other short console replies. */
    public static final long CONSOLE_MAX_MS = 3_000;
    /** Overall wait for KEYGEN / KEM INIT / PAIRING (Tropic SPI). */
    public static final long CONSOLE_SLOW_MAX_MS = 30_000;

    private static final long POLL_INTERVAL_MS = 500;
    private static final int SERIAL_READ_TIMEOUT_MS = 50;
    private static final int USB_CHUNK = 4096;
    /** Chip TLS shutdown is 3 s; stay here until that pipe is quiet. */
    private static final long RESET_DRAIN_IDLE_MS = 400;
    private static final long RESET_DRAIN_MAX_MS = 4_000;

    private final String serialPortName;
    private final SerialPort serial;
    private final InputStream serialIn;
    private final OutputStream serialOut;
    private final InputStream tlsIn;
    private final OutputStream tlsOut;

    private final Object writeLock = new Object();
    private final UsbFrame.Decoder decoder = new UsbFrame.Decoder();
    private final ByteArrayOutputStream cmdBuf = new ByteArrayOutputStream();
    private final ByteArrayOutputStream secBuf = new ByteArrayOutputStream();
    private final Thread rxThread;
    /** Bumped when the reader deposits bytes, so waits can tell a wake from a timeout. */
    private int rxAdds;
    /** Reader is blocked in the tty read, with nothing waiting to deposit. */
    private boolean rxInRead;
    private boolean discarding;
    private volatile boolean closed;

    private SeUsbLink(String serialPortName, SerialPort serial) {
        this.serialPortName = serialPortName;
        this.serial = serial;
        this.serialIn = serial.getInputStream();
        this.serialOut = serial.getOutputStream();
        this.tlsIn = new TlsInputStream();
        this.tlsOut = new TlsOutputStream();
        rxThread = new Thread(this::rxLoop, "usb-cdc-rx");
        rxThread.setDaemon(true);
        rxThread.start();
    }

    public static SeUsbLink open(String serialPortName, int baudRate) throws InterruptedException {
        Objects.requireNonNull(serialPortName, "serialPortName");
        String resolved = CdcPortScan.isAuto(serialPortName) ? waitForScannedPort() : serialPortName;
        SerialPort serial = openWhenPresent(resolved, baudRate);
        LOG.info("Opened " + resolved + " @ " + baudRate);
        return new SeUsbLink(resolved, serial);
    }

    public void sendCommand(String command) throws IOException {
        Objects.requireNonNull(command, "command");
        String trimmed = command.strip();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("command must not be empty");
        }
        if (trimmed.length() > MAX_COMMAND_CHARS) {
            throw new IllegalArgumentException("command longer than " + MAX_COMMAND_CHARS + " chars");
        }
        /* TLS close can split a frame across resetConsole's idle window. The
         * unread tail stays in the decoder and swallows every later reply
         * until the process opens the port again. */
        discardStaleRx();
        writeFrame(UsbFrame.TYPE_CMD, trimmed.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Write a Secure payload (unsigned OWNER SET blob).
     */
    public void writeRaw(byte[] data) throws IOException {
        Objects.requireNonNull(data, "data");
        writeFrame(UsbFrame.TYPE_SECURE, data);
    }

    /**
     * Send ENCRYPT/DECRYPT/MANAGE/PROVISION as a command frame. The next Secure
     * frames are TLS (ClientHello) or the command reply is {@code failed}.
     */
    public void armTls(String verb) throws IOException {
        Objects.requireNonNull(verb, "verb");
        sendCommand(verb.strip() + " " + Instant.now().getEpochSecond());
    }

    /**
     * Discard leftover frames so the next {@link #transact} sees a fresh console.
     */
    public synchronized void resetConsole() {
        discardStaleRx();
    }

    /**
     * Read command-frame text until {@code idleMs} of silence after the first byte,
     * or {@code maxMs} total.
     */
    public synchronized String readConsole(long idleMs, long maxMs) throws IOException {
        return readText(cmdBuf, idleMs, maxMs);
    }

    /**
     * Read Secure-frame text (type {@code 0x01} ASCII, if any). OWNER SET apply
     * status is a command-frame line; use {@link #readConsole}.
     */
    public synchronized String readSecureConsole(long idleMs, long maxMs) throws IOException {
        return readText(secBuf, idleMs, maxMs);
    }

    public synchronized String transact(String command) throws IOException {
        return transact(command, CONSOLE_IDLE_MS, CONSOLE_MAX_MS);
    }

    public synchronized String transact(String command, long idleMs, long maxMs) throws IOException {
        sendCommand(command);
        return readConsole(idleMs, maxMs);
    }

    /**
     * One poll of Secure-frame payload (USB↔TCP forward or TLS). Command frames
     * are left in the console buffer.
     */
    public synchronized int readRaw(byte[] dest, int off, int len) throws IOException {
        return readSecure(dest, off, len);
    }

    /**
     * One poll of TLS bytes. Same as {@link #readRaw}.
     */
    public synchronized int readTls(byte[] dest, int off, int len) throws IOException {
        return readSecure(dest, off, len);
    }

    public void writeTls(byte[] src, int off, int len) throws IOException {
        Objects.requireNonNull(src, "src");
        if (len == 0) {
            return;
        }
        writeChunks(UsbFrame.TYPE_SECURE, src, off, len);
    }

    public InputStream getInputStream() {
        return tlsIn;
    }

    public OutputStream getOutputStream() {
        return tlsOut;
    }

    public synchronized boolean isOpen() {
        if (closed) {
            return false;
        }
        if (!serial.isOpen() || !Files.exists(Path.of(serialPortName))) {
            LOG.info("Serial closed");
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
        Thread rx;
        synchronized (this) {
            closed = true;
            rx = rxThread;
            notifyAll();
        }
        serial.closePort();
        if (rx != null && rx != Thread.currentThread()) {
            try {
                rx.join(1_500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void writeFrame(byte type, byte[] payload) throws IOException {
        writeChunks(type, payload, 0, payload.length);
    }

    private void writeChunks(byte type, byte[] payload, int off, int len) throws IOException {
        /* writeLock, not the buffer monitor: serialOut.write blocks in tcdrain
         * on real CDC until the board takes the bytes. The reader must keep
         * running for that whole time. */
        synchronized (writeLock) {
            synchronized (this) {
                ensureOpen();
            }
            try {
                if (len == 0) {
                    serialOut.write(UsbFrame.encode(type, payload, off, 0));
                } else {
                    for (byte[] frame : UsbFrame.encodeSplit(type, payload, off, len)) {
                        serialOut.write(frame);
                    }
                }
                serialOut.flush();
            } catch (IOException e) {
                synchronized (this) {
                    LOG.info("Serial closed");
                    markSerialGone();
                }
                throw e;
            }
        }
    }

    private String readText(ByteArrayOutputStream src, long idleMs, long maxMs) throws IOException {
        if (idleMs < 0 || maxMs < 0) {
            throw new IllegalArgumentException("idleMs and maxMs must be >= 0");
        }
        ensureOpen();
        StringBuilder out = new StringBuilder();
        StringBuilder line = new StringBuilder();
        long start = System.currentTimeMillis();
        long lastByteAt = 0L;
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
            byte[] chunk = takeAll(src);
            if (chunk.length == 0) {
                if (!isOpen()) {
                    break;
                }
                if (!awaitRx(Math.min(SERIAL_READ_TIMEOUT_MS, maxMs))) {
                    continue;
                }
                chunk = takeAll(src);
            }
            if (chunk.length == 0) {
                continue;
            }
            lastByteAt = System.currentTimeMillis();
            appendConsoleBytes(chunk, 0, chunk.length, line, out);
        }
        if (!line.isEmpty()) {
            emitConsoleLine(line.toString(), out);
        }
        return out.toString();
    }

    private int readSecure(byte[] dest, int off, int len) throws IOException {
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
        int got = take(secBuf, dest, off, len);
        if (got > 0) {
            return got;
        }
        if (!awaitRx(SERIAL_READ_TIMEOUT_MS) || !isOpen()) {
            return isOpen() ? 0 : -1;
        }
        return take(secBuf, dest, off, len);
    }

    /**
     * Wait until the reader deposits a frame or the port closes.
     * Caller holds this monitor.
     */
    private boolean awaitRx(long timeoutMs) throws IOException {
        if (timeoutMs < 1L) {
            timeoutMs = 1L;
        }
        int seen = rxAdds;
        try {
            wait(timeoutMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while reading USB");
        }
        return rxAdds != seen;
    }

    private void rxLoop() {
        byte[] buf = new byte[USB_CHUNK];
        while (true) {
            synchronized (this) {
                if (closed) {
                    notifyAll();
                    return;
                }
                rxInRead = true;
                notifyAll();
            }
            int n;
            try {
                n = serialIn.read(buf);
            } catch (SerialPortTimeoutException e) {
                synchronized (this) {
                    rxInRead = false;
                }
                continue;
            } catch (IOException e) {
                synchronized (this) {
                    rxInRead = false;
                    if (!closed) {
                        LOG.info("Serial closed");
                        markSerialGone();
                    } else {
                        notifyAll();
                    }
                }
                return;
            }
            synchronized (this) {
                rxInRead = false;
                if (closed) {
                    notifyAll();
                    return;
                }
                if (n < 0) {
                    LOG.info("Serial closed");
                    markSerialGone();
                    return;
                }
                if (n == 0) {
                    continue;
                }
                rxAdds++;
                if (!discarding) {
                    decoder.add(buf, 0, n);
                    acceptFrames();
                }
                notifyAll();
            }
        }
    }

    /** Caller holds this monitor. */
    private void acceptFrames() {
        UsbFrame.Parsed frame;
        while ((frame = decoder.take()) != null) {
            byte[] payload = frame.payload();
            if (frame.type() == UsbFrame.TYPE_CMD) {
                cmdBuf.write(payload, 0, payload.length);
            } else if (frame.type() == UsbFrame.TYPE_SECURE) {
                secBuf.write(payload, 0, payload.length);
            }
        }
    }

    private static byte[] takeAll(ByteArrayOutputStream src) {
        byte[] all = src.toByteArray();
        src.reset();
        return all;
    }

    private static int take(ByteArrayOutputStream src, byte[] dest, int off, int len) {
        byte[] all = src.toByteArray();
        if (all.length == 0) {
            return 0;
        }
        int n = Math.min(len, all.length);
        System.arraycopy(all, 0, dest, off, n);
        src.reset();
        if (n < all.length) {
            src.write(all, n, all.length - n);
        }
        return n;
    }

    /**
     * Read until the wire is quiet, then drop the decoder and both payload
     * buffers. Must run before a new command so a half-parsed frame cannot
     * consume the next reply.
     */
    private synchronized void discardStaleRx() {
        if (!isOpen()) {
            return;
        }
        discarding = true;
        try {
            long start = System.currentTimeMillis();
            long last = start;
            while (System.currentTimeMillis() - start < RESET_DRAIN_MAX_MS) {
                if (System.currentTimeMillis() - last >= RESET_DRAIN_IDLE_MS && rxInRead) {
                    break;
                }
                int seen = rxAdds;
                try {
                    wait(SERIAL_READ_TIMEOUT_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                if (rxAdds != seen) {
                    last = System.currentTimeMillis();
                }
            }
            while (!rxInRead && !closed) {
                try {
                    wait(SERIAL_READ_TIMEOUT_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            clearPending();
        } finally {
            discarding = false;
        }
    }

    private void clearPending() {
        decoder.reset();
        cmdBuf.reset();
        secBuf.reset();
    }

    /** Caller holds this monitor. */
    private void markSerialGone() {
        closed = true;
        serial.closePort();
        notifyAll();
    }

    private void ensureOpen() throws IOException {
        if (!isOpen()) {
            throw new IOException("USB serial is closed");
        }
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
                    LOG.info("Waiting for " + serialPortName + " ...");
                    waitingLogged = true;
                }
                Thread.sleep(POLL_INTERVAL_MS);
                continue;
            }
            try {
                SerialPort serial = SerialPort.getCommPort(serialPortName);
                serial.setComPortParameters(baudRate, 8, SerialPort.ONE_STOP_BIT, SerialPort.NO_PARITY);
                /* Read timeout so an idle console poll can return. Do not set
                 * WRITE_BLOCKING: that calls tcdrain and waits until the board
                 * has accepted every byte. Provision's server flight is still
                 * on the wire when the chip enters ML-DSA and stops arming USB
                 * OUT, so that wait ends only when the cable is pulled. */
                serial.setComPortTimeouts(
                        SerialPort.TIMEOUT_READ_BLOCKING,
                        SERIAL_READ_TIMEOUT_MS,
                        0);
                if (!serial.openPort()) {
                    Thread.sleep(POLL_INTERVAL_MS);
                    continue;
                }
                serial.setDTR();
                serial.setRTS();
                return serial;
            } catch (SerialPortInvalidPortException e) {
                if (!waitingLogged) {
                    LOG.info("Waiting for " + serialPortName + " ...");
                    waitingLogged = true;
                }
                Thread.sleep(POLL_INTERVAL_MS);
            }
        }
        throw new InterruptedException("Interrupted while waiting for " + serialPortName);
    }

    private static String waitForScannedPort() throws InterruptedException {
        String lastLog = null;
        while (!Thread.currentThread().isInterrupted()) {
            var seen = CdcPortScan.list();
            String chosen = CdcPortScan.choose(seen);
            if (chosen != null && Files.exists(Path.of(chosen))) {
                LOG.info("Using " + chosen);
                return chosen;
            }
            String log = CdcPortScan.waitMessage(seen);
            if (!log.equals(lastLog)) {
                LOG.info(log);
                lastLog = log;
            }
            Thread.sleep(POLL_INTERVAL_MS);
        }
        throw new InterruptedException("Interrupted while scanning for a CDC device");
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
            synchronized (SeUsbLink.this) {
                return secBuf.size();
            }
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
