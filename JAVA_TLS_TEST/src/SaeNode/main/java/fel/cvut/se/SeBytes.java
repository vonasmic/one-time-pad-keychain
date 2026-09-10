package fel.cvut.se;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/** Small shared helpers for SE wire and crypto code. */
public final class SeBytes {

    private SeBytes() {
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    public static byte[] sha384(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(data);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-384 unavailable", ex);
        }
    }

    public static String toHex(byte[] value) {
        StringBuilder builder = new StringBuilder(value.length * 2);
        for (byte b : value) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    public static int readU16Le(byte[] value, String label) throws IOException {
        if (value == null || value.length != 2) {
            throw new IOException(label + " must be 2 bytes LE");
        }
        return (value[0] & 0xFF) | ((value[1] & 0xFF) << 8);
    }

    public static byte[] u16Le(int value) {
        return new byte[] {(byte) (value & 0xFF), (byte) ((value >>> 8) & 0xFF)};
    }

    public static byte[] u32Le(int value) {
        return new byte[] {
                (byte) (value & 0xFF),
                (byte) ((value >>> 8) & 0xFF),
                (byte) ((value >>> 16) & 0xFF),
                (byte) ((value >>> 24) & 0xFF)
        };
    }

    public static int readU16Le(InputStream in) throws IOException {
        int lo = readFullyOne(in);
        int hi = readFullyOne(in);
        return lo | (hi << 8);
    }

    public static int readU32Le(InputStream in) throws IOException {
        int b0 = readFullyOne(in);
        int b1 = readFullyOne(in);
        int b2 = readFullyOne(in);
        int b3 = readFullyOne(in);
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    public static void readFully(InputStream in, byte[] dest) throws IOException {
        int off = 0;
        while (off < dest.length) {
            int n = in.read(dest, off, dest.length - off);
            if (n < 0) {
                throw new EOFException("Unexpected end of stream at offset " + off);
            }
            if (n == 0) {
                continue;
            }
            off += n;
        }
    }

    public static int readFullyOne(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) {
            throw new EOFException("Unexpected end of stream");
        }
        return b;
    }

    public static byte[] fromHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex must not be null");
        }
        String trimmed = hex.replaceAll("\\s+", "");
        if (trimmed.length() % 2 != 0) {
            throw new IllegalArgumentException("hex must have even length");
        }
        byte[] out = new byte[trimmed.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(trimmed.charAt(i * 2), 16);
            int lo = Character.digit(trimmed.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex at index " + (i * 2));
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static byte[] requireLen(byte[] value, int expected, String label) throws IOException {
        if (value == null || value.length != expected) {
            throw new IOException(label + " must be " + expected + " bytes, got "
                    + (value == null ? "null" : value.length));
        }
        return value;
    }

    public static byte[] decodeAndConcatBase64(List<String> base64Keys) {
        if (base64Keys == null || base64Keys.isEmpty()) {
            throw new IllegalArgumentException("base64Keys must not be empty");
        }
        int total = 0;
        byte[][] decoded = new byte[base64Keys.size()][];
        for (int i = 0; i < base64Keys.size(); i++) {
            String encoded = base64Keys.get(i);
            if (encoded == null || encoded.isBlank()) {
                throw new IllegalArgumentException("Key material entry must be non-blank base64");
            }
            try {
                decoded[i] = Base64.getDecoder().decode(encoded);
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Key material is not valid base64", ex);
            }
            if (decoded[i].length == 0) {
                throw new IllegalArgumentException("Decoded key material is empty");
            }
            total += decoded[i].length;
        }
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] key : decoded) {
            System.arraycopy(key, 0, out, off, key.length);
            off += key.length;
        }
        return out;
    }

    public static int decodedBase64ByteLength(List<String> base64Keys) {
        int total = 0;
        for (String encoded : base64Keys) {
            total += Base64.getDecoder().decode(encoded).length;
        }
        return total;
    }

    public static byte[] copy(byte[] value) {
        return Arrays.copyOf(value, value.length);
    }
}
