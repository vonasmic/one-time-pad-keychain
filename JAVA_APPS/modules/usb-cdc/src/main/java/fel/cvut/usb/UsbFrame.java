package fel.cvut.usb;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * CDC frame shared with NonSecure firmware: magic, type, length, payload.
 * {@code 0x00} is a console command or reply. {@code 0x01} is a Secure payload
 * (TLS record bytes or the OWNER SET blob).
 */
public final class UsbFrame {

    public static final int MAGIC = 0x6767;
    public static final byte TYPE_CMD = 0x00;
    public static final byte TYPE_SECURE = 0x01;
    public static final int HEADER_LEN = 5;
    public static final int MAX_PAYLOAD = 1024;

    private UsbFrame() {
    }

    public record Parsed(byte type, byte[] payload) {
        public Parsed {
            Objects.requireNonNull(payload, "payload");
        }
    }

    public static byte[] encode(byte type, byte[] payload) {
        Objects.requireNonNull(payload, "payload");
        return encode(type, payload, 0, payload.length);
    }

    public static byte[] encode(byte type, byte[] payload, int off, int len) {
        Objects.requireNonNull(payload, "payload");
        if (off < 0 || len < 0 || off + len > payload.length) {
            throw new IndexOutOfBoundsException();
        }
        if (type != TYPE_CMD && type != TYPE_SECURE) {
            throw new IllegalArgumentException("unsupported USB frame type");
        }
        if (len > MAX_PAYLOAD) {
            throw new IllegalArgumentException("USB frame payload longer than " + MAX_PAYLOAD);
        }
        byte[] out = new byte[HEADER_LEN + len];
        out[0] = (byte) (MAGIC & 0xFF);
        out[1] = (byte) ((MAGIC >> 8) & 0xFF);
        out[2] = type;
        out[3] = (byte) (len & 0xFF);
        out[4] = (byte) ((len >> 8) & 0xFF);
        if (len > 0) {
            System.arraycopy(payload, off, out, HEADER_LEN, len);
        }
        return out;
    }

    /** Split a long Secure body into {@link #MAX_PAYLOAD} frames. */
    public static List<byte[]> encodeSplit(byte type, byte[] payload, int off, int len) {
        Objects.requireNonNull(payload, "payload");
        if (off < 0 || len < 0 || off + len > payload.length) {
            throw new IndexOutOfBoundsException();
        }
        List<byte[]> frames = new ArrayList<>();
        int i = 0;
        while (i < len) {
            int n = Math.min(MAX_PAYLOAD, len - i);
            frames.add(encode(type, payload, off + i, n));
            i += n;
        }
        return frames;
    }

    /** Incremental decoder. Bad magic scans forward to the next {@link #MAGIC}. */
    public static final class Decoder {

        private byte[] buf = new byte[HEADER_LEN + MAX_PAYLOAD];
        private int len;

        public void add(byte[] data, int off, int n) {
            Objects.requireNonNull(data, "data");
            if (off < 0 || n < 0 || off + n > data.length) {
                throw new IndexOutOfBoundsException();
            }
            if (n == 0) {
                return;
            }
            ensure(len + n);
            System.arraycopy(data, off, buf, len, n);
            len += n;
        }

        public void reset() {
            len = 0;
        }

        public Parsed take() {
            while (len >= 2) {
                int magic = (buf[0] & 0xFF) | ((buf[1] & 0xFF) << 8);
                if (magic != MAGIC) {
                    drop(1);
                    continue;
                }
                if (len < HEADER_LEN) {
                    return null;
                }
                int type = buf[2] & 0xFF;
                int plen = (buf[3] & 0xFF) | ((buf[4] & 0xFF) << 8);
                if ((type != (TYPE_CMD & 0xFF) && type != (TYPE_SECURE & 0xFF))
                        || plen > MAX_PAYLOAD) {
                    drop(1);
                    continue;
                }
                int total = HEADER_LEN + plen;
                if (len < total) {
                    return null;
                }
                byte[] payload = plen == 0
                        ? new byte[0]
                        : Arrays.copyOfRange(buf, HEADER_LEN, total);
                drop(total);
                return new Parsed((byte) type, payload);
            }
            return null;
        }

        private void ensure(int need) {
            if (need <= buf.length) {
                return;
            }
            int cap = buf.length;
            while (cap < need) {
                cap *= 2;
            }
            buf = Arrays.copyOf(buf, cap);
        }

        private void drop(int n) {
            if (n >= len) {
                len = 0;
                return;
            }
            System.arraycopy(buf, n, buf, 0, len - n);
            len -= n;
        }
    }
}
