package fel.cvut.se;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * OWNER SET USB blob and unsigned MANAGE TLS application data. Matches firmware
 * {@code se_manage.h} ({@code se_manage_owner_set_need}, {@code se_manage_req_need},
 * {@code se_manage_rsp_encode}). USB ingest stays in {@code se_auth.c}.
 *
 * <pre>
 * OWNER SET:  u8 pw_len | pw | u16le spki_len | spki | u16le ca_len | ca
 * MANAGE req: u8 cmd | u8 pin_len | pin | u16le body_len | body
 * MANAGE rsp: u8 status | u16le msg_len | msg
 * </pre>
 */
public final class SeManage {

    public static final int CMD_KEM_INIT = 1;
    public static final int CMD_KEYGEN = 2;
    public static final int CMD_PEER_ADD = 3;
    public static final int CMD_PEER_REMOVE = 4;
    public static final int CMD_CREDS_SAE = 5;
    /** Install a client-CA-signed device leaf (cert DER only). */
    public static final int CMD_INSERT_SIGNED_CSR = 6;
    public static final int CMD_OWNER_REPLACE = 7;
    public static final int CMD_PAIRING = 8;

    public static final int OK = 0;
    public static final int ERR = 1;
    public static final int SLOT_OCC = 3;
    public static final int NOT_READY = 4;
    public static final int TAMPERED = 5;
    public static final int PEER_EXISTS = 6;
    public static final int PEER_NOT_FOUND = 7;
    public static final int PEER_FULL = 8;
    public static final int PIN_FAIL = 9;
    public static final int BAD_CMD = 10;
    public static final int PARSE = 11;
    public static final int PW_FAIL = 12;

    /** More bytes required ({@code se_manage_req_need} / {@code frame_need} return 0). */
    public static final int NEED_MORE = 0;
    /** Length or cap violated ({@code 0xffffffff} on the device). */
    public static final int NEED_FAIL = -1;

    private SeManage() {
    }

    public record OwnerSet(byte[] password, byte[] spki, byte[] saeCa) {
        public OwnerSet {
            Objects.requireNonNull(password, "password");
            Objects.requireNonNull(spki, "spki");
            saeCa = saeCa == null ? new byte[0] : SeBytes.copy(saeCa);
            password = SeBytes.copy(password);
            spki = SeBytes.copy(spki);
        }
    }

    public record Request(int cmd, byte[] pin, byte[] body) {
        public Request {
            pin = pin == null ? new byte[0] : SeBytes.copy(pin);
            body = body == null ? new byte[0] : SeBytes.copy(body);
        }
    }

    public record Reply(int status, String msg) {
        public Reply {
            msg = msg == null ? "" : msg;
        }

        public boolean ok() {
            return status == OK;
        }

        /**
         * Human-readable line for INIT / console: success msg, or
         * {@code PIN fail} / {@code KEM INIT failed} style text from the device.
         */
        public String describe() {
            if (ok()) {
                return msg.isBlank() ? "ok" : msg;
            }
            String label = statusLabel(status);
            if (msg.isBlank()) {
                return label;
            }
            if (msg.equalsIgnoreCase(label) || msg.toLowerCase().contains(label.toLowerCase())) {
                return msg;
            }
            return label + ": " + msg;
        }
    }

    /** Short name for a MANAGE TLS status byte (matches firmware msg words). */
    public static String statusLabel(int status) {
        return switch (status) {
            case OK -> "ok";
            case ERR -> "failed";
            case SLOT_OCC -> "slot occupied";
            case NOT_READY -> "not ready";
            case TAMPERED -> "DEVICE_TAMPERED";
            case PEER_EXISTS -> "PEER nickname exists";
            case PEER_NOT_FOUND -> "PEER not found";
            case PEER_FULL -> "PEER list full";
            case PIN_FAIL -> "PIN fail";
            case BAD_CMD -> "bad command";
            case PARSE -> "bad request";
            case PW_FAIL -> "password fail";
            default -> "status " + status;
        };
    }

    public static boolean pinOk(String pin) {
        if (pin == null) {
            return false;
        }
        return asciiLenOk(pin.getBytes(StandardCharsets.US_ASCII),
                SeConstants.PIN_SIZE_MIN, SeConstants.PIN_SIZE_MAX);
    }

    public static boolean passwordOk(byte[] password) {
        return asciiLenOk(password, SeConstants.OWNER_PW_MIN, SeConstants.OWNER_PW_MAX);
    }

    public static byte[] pinBytes(String pin) {
        Objects.requireNonNull(pin, "pin");
        if (!pinOk(pin)) {
            throw new IllegalArgumentException(
                    "PIN must be " + SeConstants.PIN_SIZE_MIN + "–" + SeConstants.PIN_SIZE_MAX
                            + " printable ASCII");
        }
        return pin.getBytes(StandardCharsets.US_ASCII);
    }

    public static byte[] encodeOwnerSet(byte[] password, byte[] spki, byte[] saeCa) {
        return encodeOwnerSet(new OwnerSet(password, spki, saeCa));
    }

    public static byte[] encodeOwnerSet(OwnerSet frame) {
        Objects.requireNonNull(frame, "frame");
        if (!passwordOk(frame.password())) {
            throw new IllegalArgumentException(
                    "reset password must be " + SeConstants.OWNER_PW_MIN + "–"
                            + SeConstants.OWNER_PW_MAX + " printable ASCII");
        }
        requireSpki(frame.spki());
        byte[] ca = frame.saeCa();
        if (ca.length > SeConstants.CREDS_DER_MAX) {
            throw new IllegalArgumentException("SAE CA too long");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(
                1 + frame.password().length + 2 + frame.spki().length + 2 + ca.length);
        out.write(frame.password().length);
        out.writeBytes(frame.password());
        out.writeBytes(SeBytes.u16Le(frame.spki().length));
        out.writeBytes(frame.spki());
        out.writeBytes(SeBytes.u16Le(ca.length));
        out.writeBytes(ca);
        return out.toByteArray();
    }

    /**
     * Incremental OWNER SET size, matching {@code se_manage_owner_set_need}.
     *
     * @return {@link #NEED_MORE}, {@link #NEED_FAIL}, or the complete length
     */
    public static int ownerSetNeed(byte[] buf, int got) {
        if (buf == null || got < 0 || got > buf.length) {
            return NEED_FAIL;
        }
        if (got < 1) {
            return NEED_MORE;
        }
        int pwLen = buf[0] & 0xFF;
        if (pwLen < SeConstants.OWNER_PW_MIN || pwLen > SeConstants.OWNER_PW_MAX) {
            return NEED_FAIL;
        }
        if (got < 1 + pwLen + 2) {
            return NEED_MORE;
        }
        int spkiLen = u16le(buf, 1 + pwLen);
        if (spkiLen == 0 || spkiLen > SeConstants.MLDSA_PUB_LEN) {
            return NEED_FAIL;
        }
        int off = 1 + pwLen + 2 + spkiLen;
        if (got < off + 2) {
            return NEED_MORE;
        }
        int caLen = u16le(buf, off);
        if (caLen > SeConstants.CREDS_DER_MAX) {
            return NEED_FAIL;
        }
        return off + 2 + caLen;
    }

    public static OwnerSet decodeOwnerSet(byte[] raw) throws IOException {
        Objects.requireNonNull(raw, "raw");
        int need = ownerSetNeed(raw, raw.length);
        if (need == NEED_MORE) {
            throw new EOFException("OWNER SET truncated");
        }
        if (need != raw.length) {
            throw new IOException("OWNER SET length");
        }
        int pwLen = raw[0] & 0xFF;
        byte[] password = slice(raw, 1, pwLen);
        int spkiOff = 1 + pwLen + 2;
        int spkiLen = u16le(raw, 1 + pwLen);
        byte[] spki = slice(raw, spkiOff, spkiLen);
        int caOff = spkiOff + spkiLen + 2;
        int caLen = u16le(raw, spkiOff + spkiLen);
        byte[] ca = slice(raw, caOff, caLen);
        return new OwnerSet(password, spki, ca);
    }

    public static byte[] encodeRequest(int cmd, byte[] pin, byte[] body) {
        return encodeRequest(new Request(cmd, pin, body));
    }

    public static byte[] encodeRequest(Request request) {
        Objects.requireNonNull(request, "request");
        if (request.cmd() < 0 || request.cmd() > 0xFF) {
            throw new IllegalArgumentException("MANAGE cmd");
        }
        byte[] pin = request.pin();
        byte[] body = request.body();
        if (pin.length > SeConstants.PIN_SIZE_MAX) {
            throw new IllegalArgumentException("PIN too long");
        }
        if (body.length > SeConstants.MANAGE_BODY_MAX) {
            throw new IllegalArgumentException("MANAGE body too long");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + 1 + pin.length + 2 + body.length);
        out.write(request.cmd());
        out.write(pin.length);
        out.writeBytes(pin);
        out.writeBytes(SeBytes.u16Le(body.length));
        out.writeBytes(body);
        return out.toByteArray();
    }

    /**
 * Incremental MANAGE request size, matching {@code se_manage_req_need}.
     *
     * @return {@link #NEED_MORE}, {@link #NEED_FAIL}, or the complete length
     */
    public static int requestNeed(byte[] buf, int got) {
        if (buf == null || got < 0 || got > buf.length) {
            return NEED_FAIL;
        }
        if (got < 2) {
            return NEED_MORE;
        }
        int pinLen = buf[1] & 0xFF;
        if (pinLen > SeConstants.PIN_SIZE_MAX) {
            return NEED_FAIL;
        }
        if (got < 2 + pinLen + 2) {
            return NEED_MORE;
        }
        int bodyLen = u16le(buf, 2 + pinLen);
        if (bodyLen > SeConstants.MANAGE_BODY_MAX) {
            return NEED_FAIL;
        }
        return 2 + pinLen + 2 + bodyLen;
    }

    public static Request decodeRequest(byte[] raw) throws IOException {
        Objects.requireNonNull(raw, "raw");
        int need = requestNeed(raw, raw.length);
        if (need == NEED_MORE) {
            throw new EOFException("MANAGE request truncated");
        }
        if (need != raw.length) {
            throw new IOException("MANAGE request length");
        }
        int pinLen = raw[1] & 0xFF;
        byte[] pin = slice(raw, 2, pinLen);
        int bodyOff = 2 + pinLen + 2;
        int bodyLen = u16le(raw, 2 + pinLen);
        byte[] body = slice(raw, bodyOff, bodyLen);
        return new Request(raw[0] & 0xFF, pin, body);
    }

    public static byte[] encodeReply(Reply reply) {
        Objects.requireNonNull(reply, "reply");
        if (reply.status() < 0 || reply.status() > 0xFF) {
            throw new IllegalArgumentException("MANAGE status");
        }
        byte[] msg = reply.msg().getBytes(StandardCharsets.US_ASCII);
        if (msg.length > SeConstants.MANAGE_MSG_MAX) {
            throw new IllegalArgumentException("MANAGE message too long");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + 2 + msg.length);
        out.write(reply.status());
        out.writeBytes(SeBytes.u16Le(msg.length));
        out.writeBytes(msg);
        return out.toByteArray();
    }

    public static Reply readReply(InputStream in) throws IOException {
        Objects.requireNonNull(in, "in");
        int status = SeBytes.readFullyOne(in);
        int msgLen = SeBytes.readU16Le(in);
        if (msgLen > SeConstants.MANAGE_MSG_MAX) {
            throw new IOException("MANAGE message too long");
        }
        byte[] msg = new byte[msgLen];
        SeBytes.readFully(in, msg);
        return new Reply(status, new String(msg, StandardCharsets.US_ASCII));
    }

    public static Reply decodeReply(byte[] raw) throws IOException {
        Objects.requireNonNull(raw, "raw");
        return readReply(new ByteArrayInputStream(raw));
    }

    public static byte[] encodePeerAddBody(String name, byte[] hash48) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(hash48, "hash");
        byte[] nb = name.getBytes(StandardCharsets.US_ASCII);
        if (nb.length < 1 || nb.length > SeConstants.PEER_NAME_MAX
                || hash48.length != SeConstants.PEER_HASH_LEN) {
            throw new IllegalArgumentException("PEER ADD body");
        }
        ByteArrayOutputStream extra = new ByteArrayOutputStream(1 + nb.length + hash48.length);
        extra.write(nb.length);
        extra.writeBytes(nb);
        extra.writeBytes(hash48);
        return extra.toByteArray();
    }

    public static byte[] encodePeerRemoveBody(String name) {
        Objects.requireNonNull(name, "name");
        byte[] nb = name.getBytes(StandardCharsets.US_ASCII);
        if (nb.length < 1 || nb.length > SeConstants.PEER_NAME_MAX) {
            throw new IllegalArgumentException("PEER REMOVE body");
        }
        ByteArrayOutputStream extra = new ByteArrayOutputStream(1 + nb.length);
        extra.write(nb.length);
        extra.writeBytes(nb);
        return extra.toByteArray();
    }

    public static byte[] encodeOwnerReplaceBody(byte[] oldPassword, byte[] newPassword, byte[] spki) {
        Objects.requireNonNull(oldPassword, "oldPassword");
        Objects.requireNonNull(newPassword, "newPassword");
        Objects.requireNonNull(spki, "spki");
        if (!passwordOk(oldPassword) || !passwordOk(newPassword)) {
            throw new IllegalArgumentException(
                    "reset password must be " + SeConstants.OWNER_PW_MIN + "–"
                            + SeConstants.OWNER_PW_MAX + " printable ASCII");
        }
        requireSpki(spki);
        ByteArrayOutputStream out = new ByteArrayOutputStream(
                1 + oldPassword.length + 1 + newPassword.length + 2 + spki.length);
        out.write(oldPassword.length);
        out.writeBytes(oldPassword);
        out.write(newPassword.length);
        out.writeBytes(newPassword);
        out.writeBytes(SeBytes.u16Le(spki.length));
        out.writeBytes(spki);
        return out.toByteArray();
    }

    public static byte[] encodeDeviceCertBody(byte[] certDer) {
        Objects.requireNonNull(certDer, "certDer");
        if (certDer.length == 0 || certDer.length > SeConstants.CREDS_DER_MAX) {
            throw new IllegalArgumentException("device cert DER length");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(2 + certDer.length);
        out.writeBytes(SeBytes.u16Le(certDer.length));
        out.writeBytes(certDer);
        return out.toByteArray();
    }

    public static byte[] encodePairingBody(int slot) {
        if (slot < 1 || slot > 3) {
            throw new IllegalArgumentException("PAIRING slot must be 1–3");
        }
        return new byte[] {(byte) slot};
    }

    private static void requireSpki(byte[] spki) {
        if (spki.length == 0 || spki.length > SeConstants.MLDSA_PUB_LEN) {
            throw new IllegalArgumentException("owner SPKI length");
        }
    }

    private static boolean asciiLenOk(byte[] bytes, int min, int max) {
        if (bytes == null || bytes.length < min || bytes.length > max) {
            return false;
        }
        for (byte b : bytes) {
            int c = b & 0xFF;
            if (c < 0x20 || c > 0x7e) {
                return false;
            }
        }
        return true;
    }

    private static int u16le(byte[] buf, int off) {
        return (buf[off] & 0xFF) | ((buf[off + 1] & 0xFF) << 8);
    }

    private static byte[] slice(byte[] buf, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(buf, off, out, 0, len);
        return out;
    }
}
