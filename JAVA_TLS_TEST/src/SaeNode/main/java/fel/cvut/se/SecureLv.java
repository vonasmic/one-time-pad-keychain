package fel.cvut.se;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Shared length-value envelope for SE uplink/downlink (little-endian).
 *
 * <pre>
 *   u8   version
 *   u16  count
 *   repeat count times:
 *     u16 len
 *     u8  value[len]
 * </pre>
 */
public final class SecureLv {

    private static final int MAX_U16 = 0xFFFF;
    private static final int MAX_ITEM_BYTES = SeConstants.QKD_MAX_BYTES;

    private SecureLv() {
    }

    public record Envelope(int version, List<byte[]> items) {
        public Envelope {
            if (version < 0 || version > 0xFF) {
                throw new IllegalArgumentException("version out of range: " + version);
            }
            Objects.requireNonNull(items, "items must not be null");
            if (items.size() > MAX_U16) {
                throw new IllegalArgumentException("too many items: " + items.size());
            }
            for (byte[] item : items) {
                Objects.requireNonNull(item, "item must not be null");
                if (item.length > MAX_U16) {
                    throw new IllegalArgumentException("item longer than 65535: " + item.length);
                }
            }
            items = List.copyOf(items);
        }
    }

    public static byte[] encode(int version, List<byte[]> items) {
        Envelope envelope = new Envelope(version, items);
        ByteArrayOutputStream out = new ByteArrayOutputStream(estimateSize(envelope));
        out.write(envelope.version() & 0xFF);
        writeU16(out, envelope.items().size());
        for (byte[] item : envelope.items()) {
            writeU16(out, item.length);
            out.writeBytes(item);
        }
        return out.toByteArray();
    }

    /**
     * Reads one complete envelope from {@code in} without waiting for EOF.
     * Stops after the last item so the peer can keep the stream open for a reply.
     */
    public static Envelope readFrom(InputStream in) throws IOException {
        Objects.requireNonNull(in, "in must not be null");
        int version = readFullyOne(in);
        int count = readU16(in);
        List<byte[]> items = new ArrayList<>(count);
        long payloadBytes = 0L;
        for (int i = 0; i < count; i++) {
            int len = readU16(in);
            payloadBytes += len;
            if (payloadBytes > MAX_ITEM_BYTES) {
                throw new IOException("LV payload exceeds " + MAX_ITEM_BYTES + " bytes");
            }
            byte[] item = new byte[len];
            readFully(in, item);
            items.add(item);
        }
        return new Envelope(version, items);
    }

    public static Envelope decode(byte[] raw) throws IOException {
        Objects.requireNonNull(raw, "raw must not be null");
        return readFrom(new java.io.ByteArrayInputStream(raw));
    }

    private static int estimateSize(Envelope envelope) {
        int size = 1 + 2;
        for (byte[] item : envelope.items()) {
            size += 2 + item.length;
        }
        return size;
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >>> 8) & 0xFF);
    }

    private static int readU16(InputStream in) throws IOException {
        int lo = readFullyOne(in);
        int hi = readFullyOne(in);
        return lo | (hi << 8);
    }

    private static int readFullyOne(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) {
            throw new EOFException("Unexpected end of LV stream");
        }
        return b;
    }

    private static void readFully(InputStream in, byte[] dest) throws IOException {
        int off = 0;
        while (off < dest.length) {
            int n = in.read(dest, off, dest.length - off);
            if (n < 0) {
                throw new EOFException("Unexpected end of LV stream at offset " + off);
            }
            off += n;
        }
    }
}
