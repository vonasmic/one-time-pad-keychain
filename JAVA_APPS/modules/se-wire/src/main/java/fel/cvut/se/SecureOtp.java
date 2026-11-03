package fel.cvut.se;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * TLS OTP framing after mTLS (not an LV envelope). Matches firmware {@code secure_otp.h}.
 *
 * <pre>
 * ENCRYPT request:  u8 pin_len | pin | u32 msg_len LE | plaintext
 * ENCRYPT reply:    u32 n_pads LE | repeat: u16 slot LE | u16 len LE | chunk
 * DECRYPT request:  u8 pin_len | pin | ENCRYPT reply (unchanged)
 * DECRYPT reply:    u32 n_pads LE | repeat: u16 len LE | chunk
 * Error reply:      u32 n_pads LE = 0 | u32 err_code LE
 * </pre>
 */
public final class SecureOtp {

    public static final int ERR_EXHAUSTED = 1;
    public static final int ERR_PARSE = 3;
    public static final int ERR_PIN = 4;
    public static final int ERR_TAMPERED = 5;
    public static final int ERR_FAIL = 255;

    private SecureOtp() {
    }

    /** Device refused the OTP request; {@link #code()} is the firmware {@code SECURE_OTP_ERR_*} value. */
    public static final class OtpException extends IOException {
        private final int code;

        public OtpException(int code) {
            super(messageFor(code));
            this.code = code;
        }

        public int code() {
            return code;
        }

        public static String nameFor(int code) {
            return switch (code) {
                case ERR_EXHAUSTED -> "EXHAUSTED";
                case ERR_PARSE -> "PARSE";
                case ERR_PIN -> "PIN";
                case ERR_TAMPERED -> "TAMPERED";
                case ERR_FAIL -> "FAIL";
                default -> "UNKNOWN";
            };
        }

        private static String messageFor(int code) {
            String meaning = switch (code) {
                case ERR_EXHAUSTED -> "pad stream exhausted";
                case ERR_PARSE -> "bad OTP framing";
                case ERR_PIN -> "PIN failed";
                case ERR_TAMPERED -> "DEVICE_TAMPERED";
                case ERR_FAIL -> "OTP failed";
                default -> "OTP failed";
            };
            return "OTP error " + code + " (" + nameFor(code) + "): " + meaning;
        }
    }

    public record EncryptPad(int logicalSlot, byte[] chunk) {
        public EncryptPad {
            if (logicalSlot < 0 || logicalSlot > 0xFFFF) {
                throw new IllegalArgumentException("logicalSlot out of range: " + logicalSlot);
            }
            Objects.requireNonNull(chunk, "chunk must not be null");
            if (chunk.length == 0 || chunk.length > 0xFFFF) {
                throw new IllegalArgumentException("chunk length out of range: " + chunk.length);
            }
            chunk = SeBytes.copy(chunk);
        }
    }

    public record EncryptReply(List<EncryptPad> pads) {
        public EncryptReply {
            Objects.requireNonNull(pads, "pads must not be null");
            if (pads.isEmpty() || pads.size() > SeConstants.PAD_COUNT) {
                throw new IllegalArgumentException("n_pads out of range: " + pads.size());
            }
            pads = List.copyOf(pads);
        }

        public byte[] toBytes() {
            return encodeEncryptReply(this);
        }
    }

    public record DecryptReply(List<byte[]> chunks) {
        public DecryptReply {
            Objects.requireNonNull(chunks, "chunks must not be null");
            if (chunks.isEmpty() || chunks.size() > SeConstants.PAD_COUNT) {
                throw new IllegalArgumentException("n_pads out of range: " + chunks.size());
            }
            List<byte[]> copy = new ArrayList<>(chunks.size());
            for (byte[] chunk : chunks) {
                Objects.requireNonNull(chunk, "chunk must not be null");
                if (chunk.length == 0 || chunk.length > 0xFFFF) {
                    throw new IllegalArgumentException("chunk length out of range: " + chunk.length);
                }
                copy.add(SeBytes.copy(chunk));
            }
            chunks = List.copyOf(copy);
        }

        public byte[] plaintext() {
            int total = 0;
            for (byte[] chunk : chunks) {
                total += chunk.length;
            }
            byte[] out = new byte[total];
            int off = 0;
            for (byte[] chunk : chunks) {
                System.arraycopy(chunk, 0, out, off, chunk.length);
                off += chunk.length;
            }
            return out;
        }
    }

    public static byte[] encodeEncryptRequest(byte[] pin, byte[] plaintext) {
        byte[] pinBytes = requirePin(pin);
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        if (plaintext.length == 0) {
            throw new IllegalArgumentException("plaintext must not be empty");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + pinBytes.length + 4 + plaintext.length);
        out.write(pinBytes.length);
        out.writeBytes(pinBytes);
        out.writeBytes(SeBytes.u32Le(plaintext.length));
        out.writeBytes(plaintext);
        return out.toByteArray();
    }

    public static byte[] encodeEncryptRequest(String pin, byte[] plaintext) {
        return encodeEncryptRequest(pinBytes(pin), plaintext);
    }

    public static byte[] encodeDecryptRequest(byte[] pin, byte[] encryptReply) {
        byte[] pinBytes = requirePin(pin);
        Objects.requireNonNull(encryptReply, "encryptReply must not be null");
        if (encryptReply.length < 4) {
            throw new IllegalArgumentException("encrypt reply too short");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + pinBytes.length + encryptReply.length);
        out.write(pinBytes.length);
        out.writeBytes(pinBytes);
        out.writeBytes(encryptReply);
        return out.toByteArray();
    }

    public static byte[] encodeDecryptRequest(String pin, byte[] encryptReply) {
        return encodeDecryptRequest(pinBytes(pin), encryptReply);
    }

    public static byte[] encodeEncryptReply(EncryptReply reply) {
        Objects.requireNonNull(reply, "reply must not be null");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(SeBytes.u32Le(reply.pads().size()));
        for (EncryptPad pad : reply.pads()) {
            out.writeBytes(SeBytes.u16Le(pad.logicalSlot()));
            out.writeBytes(SeBytes.u16Le(pad.chunk().length));
            out.writeBytes(pad.chunk());
        }
        return out.toByteArray();
    }

    public static byte[] encodeDecryptReply(DecryptReply reply) {
        Objects.requireNonNull(reply, "reply must not be null");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(SeBytes.u32Le(reply.chunks().size()));
        for (byte[] chunk : reply.chunks()) {
            out.writeBytes(SeBytes.u16Le(chunk.length));
            out.writeBytes(chunk);
        }
        return out.toByteArray();
    }

    public static EncryptReply readEncryptReply(InputStream in) throws IOException {
        Objects.requireNonNull(in, "in must not be null");
        int nPads = requirePadCount(readNPadsOrThrow(in));
        List<EncryptPad> pads = new ArrayList<>(nPads);
        for (int i = 0; i < nPads; i++) {
            int slot = SeBytes.readU16Le(in);
            int len = SeBytes.readU16Le(in);
            if (len == 0) {
                throw new IOException("encrypt pad chunk length is 0");
            }
            byte[] chunk = new byte[len];
            SeBytes.readFully(in, chunk);
            pads.add(new EncryptPad(slot, chunk));
        }
        return new EncryptReply(pads);
    }

    public static EncryptReply decodeEncryptReply(byte[] raw) throws IOException {
        Objects.requireNonNull(raw, "raw must not be null");
        return readEncryptReply(new ByteArrayInputStream(raw));
    }

    public static DecryptReply readDecryptReply(InputStream in) throws IOException {
        Objects.requireNonNull(in, "in must not be null");
        int nPads = requirePadCount(readNPadsOrThrow(in));
        List<byte[]> chunks = new ArrayList<>(nPads);
        for (int i = 0; i < nPads; i++) {
            int len = SeBytes.readU16Le(in);
            if (len == 0) {
                throw new IOException("decrypt pad chunk length is 0");
            }
            byte[] chunk = new byte[len];
            SeBytes.readFully(in, chunk);
            chunks.add(chunk);
        }
        return new DecryptReply(chunks);
    }

    public static DecryptReply decodeDecryptReply(byte[] raw) throws IOException {
        Objects.requireNonNull(raw, "raw must not be null");
        return readDecryptReply(new ByteArrayInputStream(raw));
    }

    private static byte[] pinBytes(String pin) {
        Objects.requireNonNull(pin, "pin must not be null");
        return pin.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] requirePin(byte[] pin) {
        Objects.requireNonNull(pin, "pin must not be null");
        if (pin.length < SeConstants.PIN_SIZE_MIN || pin.length > SeConstants.PIN_SIZE_MAX) {
            throw new IllegalArgumentException(
                    "PIN must be " + SeConstants.PIN_SIZE_MIN + "–" + SeConstants.PIN_SIZE_MAX + " bytes");
        }
        return pin;
    }

    private static int readNPadsOrThrow(InputStream in) throws IOException {
        int nPads = SeBytes.readU32Le(in);
        if (nPads == 0) {
            throw new OtpException(SeBytes.readU32Le(in));
        }
        return nPads;
    }

    private static int requirePadCount(int nPads) throws IOException {
        if (nPads <= 0 || nPads > SeConstants.PAD_COUNT) {
            throw new IOException("n_pads out of range: " + nPads);
        }
        return nPads;
    }
}
