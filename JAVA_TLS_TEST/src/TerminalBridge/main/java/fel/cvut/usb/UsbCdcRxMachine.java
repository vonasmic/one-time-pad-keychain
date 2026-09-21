package fel.cvut.usb;

import fel.cvut.se.SeUsbDump;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Objects;
import java.util.Queue;

/**
 * CDC leftover machine: {@code 0xB1} dump frames, ASCII ({@code failed} abort), glued
 * ClientHello {@code 0x16}. Dump bodies may contain {@code 0x16}; length prefix wins.
 * {@link #feed} takes USB chunks; {@link #takeTls} returns TLS bytes only.
 */
public final class UsbCdcRxMachine {

    public static final int DUMP_MAGIC = SeUsbDump.MAGIC;
    public static final int DUMP_HDR_LEN = SeUsbDump.HDR_LEN;
    public static final int DUMP_BODY_MAX = SeUsbDump.BODY_MAX;

    /** Print dump / ASCII / handshake the way {@link SeUsbLink} did before the extract. */
    public static final UsbCdcListener PRINT = new UsbCdcListener() {
        @Override
        public void onDump(int status, byte[] body) {
            System.out.println("[usb] dump status=" + status + " len=" + body.length);
        }

        @Override
        public void onPreTlsAscii(byte[] data, int off, int len) {
            System.out.print(new String(data, off, len, StandardCharsets.ISO_8859_1));
            System.out.flush();
        }

        @Override
        public void onTlsHandshakeDetected() {
            System.out.println("[usb] TLS Handshake detected");
        }
    };

    private final UsbCdcListener listener;
    private final Queue<SeUsbDump> dumps = new ArrayDeque<>();

    private byte[] leftover = new byte[0];
    private int leftoverPos;
    private int leftoverLen;
    private boolean tlsActive;
    private String tlsArmFailure;
    private final StringBuilder asciiLine = new StringBuilder();

    public UsbCdcRxMachine() {
        this(PRINT);
    }

    public UsbCdcRxMachine(UsbCdcListener listener) {
        this.listener = Objects.requireNonNull(listener, "listener");
    }

    public void feed(byte[] src, int off, int len) {
        Objects.requireNonNull(src, "src");
        if (off < 0 || len < 0 || off + len > src.length) {
            throw new IndexOutOfBoundsException();
        }
        appendLeftover(src, off, len);
    }

    /**
     * Drain TLS after ClientHello. Returns 0 if more CDC bytes are needed (or {@code len} is 0).
     */
    public int takeTls(byte[] dest, int off, int len) {
        Objects.requireNonNull(dest, "dest");
        if (off < 0 || len < 0 || off + len > dest.length) {
            throw new IndexOutOfBoundsException();
        }
        if (tlsActive) {
            return drainLeftover(dest, off, len);
        }
        pumpPreTls();
        if (tlsActive) {
            return drainLeftover(dest, off, len);
        }
        return 0;
    }

    /**
     * Next complete dump, or {@code null} if more CDC bytes are needed.
     */
    public SeUsbDump takeDump() {
        if (tlsActive) {
            return null;
        }
        if (!dumps.isEmpty()) {
            return dumps.poll();
        }
        pumpPreTls();
        return dumps.poll();
    }

    public boolean isTlsActive() {
        return tlsActive;
    }

    public int pending() {
        return Math.max(0, leftoverLen - leftoverPos);
    }

    /**
     * {@code failed} that aborted TLS arm, or {@code null}. Clears the stored failure.
     */
    public String consumeArmFailure() {
        String msg = tlsArmFailure;
        tlsArmFailure = null;
        return msg;
    }

    public void reset() {
        tlsActive = false;
        tlsArmFailure = null;
        leftoverPos = 0;
        leftoverLen = 0;
        leftover = new byte[0];
        dumps.clear();
        asciiLine.setLength(0);
    }

    /**
     * Leave leftover in place but stop treating RX as TLS (OWNER SET / console).
     */
    public void disarmTls() {
        tlsActive = false;
        tlsArmFailure = null;
    }

    /**
     * Copy and drop leftover without dump / ClientHello parsing (ASCII console).
     */
    public byte[] takePendingRaw() {
        int n = leftoverLen - leftoverPos;
        if (n <= 0) {
            leftoverPos = 0;
            leftoverLen = 0;
            leftover = new byte[0];
            return new byte[0];
        }
        byte[] out = Arrays.copyOfRange(leftover, leftoverPos, leftoverLen);
        leftoverPos = 0;
        leftoverLen = 0;
        leftover = new byte[0];
        return out;
    }

    /** USB ASCII error / TLS-arm abort is exactly {@code failed}. */
    public static boolean isTlsArmAbort(String body) {
        return body != null && body.strip().equals("failed");
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

    private void pumpPreTls() {
        while (leftoverPos < leftoverLen && !tlsActive) {
            int b = leftover[leftoverPos] & 0xFF;
            if (b == DUMP_MAGIC) {
                if (!takeDumpFrame()) {
                    compactLeftover();
                    return;
                }
                continue;
            }
            if (b == 0x16) {
                tlsActive = true;
                listener.onTlsHandshakeDetected();
                compactLeftover();
                return;
            }
            int end = leftoverPos + 1;
            while (end < leftoverLen) {
                int c = leftover[end] & 0xFF;
                if (c == DUMP_MAGIC || c == 0x16) {
                    break;
                }
                end++;
            }
            emitPreTlsAscii(leftoverPos, end);
            leftoverPos = end;
        }
        compactLeftover();
    }

    /**
     * @return false when more bytes are required for a complete dump header/body
     */
    private boolean takeDumpFrame() {
        if (leftoverLen - leftoverPos < DUMP_HDR_LEN) {
            return false;
        }
        int bodyLen = (leftover[leftoverPos + 2] & 0xFF)
                | ((leftover[leftoverPos + 3] & 0xFF) << 8);
        if (bodyLen > DUMP_BODY_MAX) {
            leftoverPos++;
            return true;
        }
        int total = DUMP_HDR_LEN + bodyLen;
        if (leftoverLen - leftoverPos < total) {
            return false;
        }
        int status = leftover[leftoverPos + 1] & 0xFF;
        byte[] body = new byte[bodyLen];
        System.arraycopy(leftover, leftoverPos + DUMP_HDR_LEN, body, 0, bodyLen);
        leftoverPos += total;
        SeUsbDump dump = new SeUsbDump(status, body);
        dumps.add(dump);
        listener.onDump(status, dump.body);
        return true;
    }

    private void emitPreTlsAscii(int from, int to) {
        if (to <= from) {
            return;
        }
        listener.onPreTlsAscii(leftover, from, to - from);
        for (int i = from; i < to; i++) {
            byte c = leftover[i];
            if (c == '\r') {
                continue;
            }
            if (c == '\n') {
                noteAsciiLine(asciiLine.toString());
                asciiLine.setLength(0);
            } else {
                asciiLine.append((char) (c & 0xFF));
            }
        }
    }

    private void noteAsciiLine(String line) {
        if (tlsArmFailure == null && isTlsArmAbort(line)) {
            tlsArmFailure = "failed";
        }
    }
}
