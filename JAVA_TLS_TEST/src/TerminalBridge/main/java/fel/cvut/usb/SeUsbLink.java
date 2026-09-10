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
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

/**
 * USB CDC ACM console: ASCII commands ({@link #transact} / {@link #readConsole}), then
 * opaque TLS bytes after ClientHello {@code 0x16}. Framed {@code DEBUG:<text>:DEBUG}
 * status is printed and never returned as TLS; a glued hello after {@code :DEBUG} is.
 *
 * <p>After application data, {@link javax.net.ssl.SSLSocket#close()} sends
 * {@code close_notify}. The chip stays in TLS until that alert (and its own)
 * complete, then {@link #resetConsole} drains DEBUG back to ASCII.
 *
 * <p>Serial path is {@code USB_SERIAL_PORT}. SAE host/ports are the process
 * {@code NODE_HOSTNAME} / {@code NODE_NATIVE_PORT} / {@code NODE_TERMINAL_PORT}.
 */
public final class SeUsbLink implements AutoCloseable {

    public static final String DEFAULT_PORT = "/dev/ttyACM0";
    public static final int DEFAULT_BAUD = 115200;
    /**
     * Firmware {@code TLS_CMD_MAX}: fits {@code TROPIC PAIRING LOAD <slot> <64-hex> <64-hex>}.
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
    private static final String DEBUG_PREFIX = "DEBUG:";
    private static final String DEBUG_SUFFIX = ":DEBUG";
    private static final byte[] DEBUG_PREFIX_BYTES = DEBUG_PREFIX.getBytes(StandardCharsets.US_ASCII);
    private static final byte[] DEBUG_SUFFIX_BYTES = DEBUG_SUFFIX.getBytes(StandardCharsets.US_ASCII);
    /** Firmware debug frames fit in 192 bytes; wait a bit longer for a split USB read. */
    private static final int MAX_DEBUG_FRAME = 256;

    private final String serialPortName;
    private final SerialPort serial;
    private final InputStream serialIn;
    private final OutputStream serialOut;
    private final InputStream tlsIn;
    private final OutputStream tlsOut;

    private final byte[] scratch = new byte[USB_CHUNK];
    private byte[] leftover = new byte[0];
    private int leftoverPos;
    private int leftoverLen;
    private boolean tlsActive;
    private String tlsArmFailure;
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
        clearTlsParseState();
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
        tlsActive = false;
        tlsArmFailure = null;
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
     * Firmware refusals ({@code TLS refused}, {@code TLS start failed}) throw instead of
     * leaving {@link javax.net.ssl.SSLSocket#startHandshake()} blocked forever.
     */
    public void armTls(String verb) throws IOException {
        Objects.requireNonNull(verb, "verb");
        sendCommand(verb.strip() + " " + Instant.now().getEpochSecond());
        awaitTlsOrThrow(TLS_ARM_MAX_MS);
    }

    /**
     * Pump CDC until ClientHello ({@code 0x16}) or a TLS-arm abort debug frame.
     * Leaves hello bytes in leftover for the next {@link #readTls}.
     */
    public synchronized void awaitTlsOrThrow(long maxMs) throws IOException {
        if (maxMs < 0) {
            throw new IllegalArgumentException("maxMs must be >= 0");
        }
        ensureOpen();
        throwIfTlsArmFailed();
        long start = System.currentTimeMillis();
        while (!tlsActive) {
            throwIfTlsArmFailed();
            if (System.currentTimeMillis() - start >= maxMs) {
                throw new IOException("TLS start timed out");
            }
            if (leftoverLen > leftoverPos) {
                int pending = leftoverLen - leftoverPos;
                takePreTls(scratch, 0, 0);
                throwIfTlsArmFailed();
                if (tlsActive) {
                    return;
                }
                if (leftoverLen - leftoverPos < pending) {
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
                appendLeftover(scratch, 0, n);
            }
        }
    }

    /**
     * Drain CDC RX so the next {@link #transact} sees ASCII console.
     * Call after {@link javax.net.ssl.SSLSocket#close()} so {@code close_notify}
     * has already been exchanged.
     */
    public synchronized void resetConsole() {
        clearTlsParseState();
        leftover = new byte[0];
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
     * {@code DEBUG:<text>:DEBUG} wrappers are stripped. Does not treat {@code 0x16} as TLS.
     */
    public synchronized String readConsole(long idleMs, long maxMs) throws IOException {
        if (idleMs < 0 || maxMs < 0) {
            throw new IllegalArgumentException("idleMs and maxMs must be >= 0");
        }
        ensureOpen();
        tlsActive = false;
        StringBuilder out = new StringBuilder();
        StringBuilder line = new StringBuilder();
        long start = System.currentTimeMillis();
        long lastByteAt = 0L;
        if (leftoverLen - leftoverPos > 0) {
            lastByteAt = start;
            appendConsoleBytes(leftover, leftoverPos, leftoverLen - leftoverPos, line, out);
            leftoverPos = 0;
            leftoverLen = 0;
            leftover = new byte[0];
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

    /**
     * One serial poll. Returns TLS bytes only (0 on idle / debug, -1 if the port closed).
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
        if (tlsActive) {
            int fromLeftover = drainLeftover(dest, off, len);
            if (fromLeftover > 0) {
                return fromLeftover;
            }
        } else if (leftoverLen > leftoverPos) {
            int fromFrame = takePreTls(dest, off, len);
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
        appendLeftover(scratch, 0, n);
        if (tlsActive) {
            return drainLeftover(dest, off, len);
        }
        int fromFrame = takePreTls(dest, off, len);
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

    private int drainLeftover(byte[] dest, int off, int len) {
        if (leftoverLen - leftoverPos <= 0) {
            return 0;
        }
        int n = Math.min(len, leftoverLen - leftoverPos);
        System.arraycopy(leftover, leftoverPos, dest, off, n);
        leftoverPos += n;
        return n;
    }

    private void appendLeftover(byte[] src, int off, int len) {
        if (len <= 0) {
            return;
        }
        int keep = leftoverLen - leftoverPos;
        byte[] next = new byte[keep + len];
        if (keep > 0) {
            System.arraycopy(leftover, leftoverPos, next, 0, keep);
        }
        System.arraycopy(src, off, next, keep, len);
        leftover = next;
        leftoverPos = 0;
        leftoverLen = next.length;
    }

    private void compactLeftover() {
        if (leftoverPos == 0) {
            return;
        }
        int keep = leftoverLen - leftoverPos;
        leftover = keep <= 0 ? new byte[0] : Arrays.copyOfRange(leftover, leftoverPos, leftoverLen);
        leftoverPos = 0;
        leftoverLen = leftover.length;
    }

    /**
     * Strip complete {@code DEBUG:<text>:DEBUG} frames. Remaining {@code 0x16} becomes TLS.
     */
    private int takePreTls(byte[] dest, int off, int len) {
        while (leftoverPos < leftoverLen) {
            skipCrlf();
            if (leftoverPos >= leftoverLen) {
                break;
            }
            if (startsWithDebugPrefix()) {
                int suffixAt = indexOfDebugSuffix(leftoverPos + DEBUG_PREFIX_BYTES.length);
                if (suffixAt < 0) {
                    if (leftoverLen - leftoverPos > MAX_DEBUG_FRAME) {
                        emitPreTlsAscii(leftoverPos, leftoverLen);
                        leftoverPos = leftoverLen;
                        break;
                    }
                    compactLeftover();
                    return 0;
                }
                emitDebugFrame(leftoverPos + DEBUG_PREFIX_BYTES.length, suffixAt);
                leftoverPos = suffixAt + DEBUG_SUFFIX_BYTES.length;
                continue;
            }
            if (isIncompleteDebugPrefix()) {
                compactLeftover();
                return 0;
            }
            if ((leftover[leftoverPos] & 0xFF) == 0x16) {
                tlsActive = true;
                System.out.println("[usb] TLS Handshake detected");
                compactLeftover();
                return drainLeftover(dest, off, len);
            }
            int end = leftoverPos + 1;
            while (end < leftoverLen) {
                if ((leftover[end] & 0xFF) == 0x16) {
                    break;
                }
                if (startsWithAt(end, DEBUG_PREFIX_BYTES)) {
                    break;
                }
                end++;
            }
            emitPreTlsAscii(leftoverPos, end);
            leftoverPos = end;
        }
        compactLeftover();
        return 0;
    }

    private void skipCrlf() {
        while (leftoverPos < leftoverLen) {
            byte b = leftover[leftoverPos];
            if (b != '\r' && b != '\n') {
                return;
            }
            leftoverPos++;
        }
    }

    private boolean startsWithDebugPrefix() {
        return startsWithAt(leftoverPos, DEBUG_PREFIX_BYTES);
    }

    private boolean startsWithAt(int from, byte[] needle) {
        if (from < 0 || leftoverLen - from < needle.length) {
            return false;
        }
        for (int i = 0; i < needle.length; i++) {
            if (leftover[from + i] != needle[i]) {
                return false;
            }
        }
        return true;
    }

    private boolean isIncompleteDebugPrefix() {
        int n = leftoverLen - leftoverPos;
        if (n <= 0 || n >= DEBUG_PREFIX_BYTES.length) {
            return false;
        }
        for (int i = 0; i < n; i++) {
            if (leftover[leftoverPos + i] != DEBUG_PREFIX_BYTES[i]) {
                return false;
            }
        }
        return true;
    }

    private int indexOfDebugSuffix(int from) {
        int last = leftoverLen - DEBUG_SUFFIX_BYTES.length;
        for (int i = from; i <= last; i++) {
            if (startsWithAt(i, DEBUG_SUFFIX_BYTES)) {
                return i;
            }
        }
        return -1;
    }

    private void emitDebugFrame(int bodyFrom, int bodyTo) {
        String body = new String(leftover, bodyFrom, bodyTo - bodyFrom, StandardCharsets.ISO_8859_1)
                .strip();
        if (!body.isEmpty()) {
            System.out.println(DEBUG_PREFIX + " " + body);
            if (tlsArmFailure == null && isTlsArmAbort(body)) {
                tlsArmFailure = body;
            }
        }
    }

    /** Firmware DEBUG body that means TLS was not armed (no ClientHello will follow). */
    static boolean isTlsArmAbort(String body) {
        if (body == null || body.isBlank()) {
            return false;
        }
        String lower = body.strip().toLowerCase(Locale.ROOT);
        return lower.contains("tls start failed")
                || lower.contains("tls refused")
                || lower.startsWith("tls setup:")
                || lower.contains("tls aborted");
    }

    private void clearTlsParseState() {
        tlsActive = false;
        tlsArmFailure = null;
        leftoverPos = 0;
        leftoverLen = 0;
    }

    private void throwIfTlsArmFailed() throws IOException {
        if (tlsArmFailure == null) {
            return;
        }
        String msg = tlsArmFailure;
        tlsArmFailure = null;
        throw new IOException("TLS start failed: " + msg);
    }

    private void emitPreTlsAscii(int from, int to) {
        if (to <= from) {
            return;
        }
        System.out.print(new String(leftover, from, to - from, StandardCharsets.ISO_8859_1));
        System.out.flush();
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
        String line = stripDebugPrefix(raw);
        if (line.isEmpty()) {
            return;
        }
        System.out.println(line);
        if (!out.isEmpty()) {
            out.append('\n');
        }
        out.append(line);
    }

    private static String stripDebugPrefix(String raw) {
        String trimmed = raw.strip();
        if (trimmed.startsWith(DEBUG_PREFIX)) {
            trimmed = trimmed.substring(DEBUG_PREFIX.length()).strip();
        }
        if (trimmed.endsWith(DEBUG_SUFFIX)) {
            trimmed = trimmed.substring(0, trimmed.length() - DEBUG_SUFFIX.length()).strip();
        }
        return trimmed;
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
            return Math.max(0, leftoverLen - leftoverPos);
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
