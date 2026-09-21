package fel.cvut.se;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * USB dump frame matching firmware {@code se_usb_dump}:
 * {@code 0xB1 | u8 status | u16le body_len | body}.
 *
 * <p>Status is occupancy / protocol only ({@code ok}/{@code err}/{@code empty}/{@code refused}).
 * Tropic, TLS, and PIN failure types are not on this wire.
 */
public final class SeUsbDump {

    public static final int MAGIC = 0xB1;
    public static final int OK = 0;
    public static final int ERR = 1;
    public static final int EMPTY = 2;
    public static final int REFUSED = 3;
    public static final int HDR_LEN = 4;
    public static final int BODY_MAX = SeConstants.MLDSA_PUB_LEN;

    public final int status;
    public final byte[] body;

    public SeUsbDump(int status, byte[] body) {
        this.status = status;
        this.body = body == null ? new byte[0] : SeBytes.copy(body);
    }

    public boolean ok() {
        return status == OK;
    }

    public boolean empty() {
        return status == EMPTY;
    }

    public boolean refused() {
        return status == REFUSED;
    }

    public byte[] encode() {
        if (body.length > BODY_MAX) {
            throw new IllegalArgumentException("dump body too long");
        }
        byte[] out = new byte[HDR_LEN + body.length];
        out[0] = (byte) MAGIC;
        out[1] = (byte) status;
        byte[] n = SeBytes.u16Le(body.length);
        out[2] = n[0];
        out[3] = n[1];
        System.arraycopy(body, 0, out, HDR_LEN, body.length);
        return out;
    }

    public static SeUsbDump parse(byte[] frame) {
        Objects.requireNonNull(frame, "frame");
        if (frame.length < HDR_LEN) {
            return null;
        }
        if ((frame[0] & 0xFF) != MAGIC) {
            return null;
        }
        int len = (frame[2] & 0xFF) | ((frame[3] & 0xFF) << 8);
        if (len > BODY_MAX || frame.length < HDR_LEN + len) {
            return null;
        }
        byte[] body = new byte[len];
        System.arraycopy(frame, HDR_LEN, body, 0, len);
        return new SeUsbDump(frame[1] & 0xFF, body);
    }

    public byte[] tropicPub() {
        if (!ok() || body.length != SeConstants.ECC_PUB_LEN) {
            return null;
        }
        return SeBytes.copy(body);
    }

    public byte[] clientCsr() {
        if (!ok() || body.length != SeConstants.MLDSA_PUB_LEN) {
            return null;
        }
        return SeBytes.copy(body);
    }

    public byte[] kemPub() {
        if (!ok() || body.length != SeConstants.MLKEM_PK_LEN) {
            return null;
        }
        return SeBytes.copy(body);
    }

    public byte[] clientHash() {
        if (!ok() || body.length != SeConstants.CLIENT_HASH_LEN) {
            return null;
        }
        return SeBytes.copy(body);
    }

    /**
     * {@code TROPIC OTP LEFT}: four little-endian u32 — enc left, enc cap, dec left, dec cap.
     */
    public int[] otpLeft() {
        if (!ok() || body.length != 16) {
            return null;
        }
        int[] q = new int[4];
        for (int i = 0; i < 4; i++) {
            int o = i * 4;
            q[i] = (body[o] & 0xFF)
                    | ((body[o + 1] & 0xFF) << 8)
                    | ((body[o + 2] & 0xFF) << 16)
                    | ((body[o + 3] & 0xFF) << 24);
        }
        return q;
    }

    /**
     * {@code PEER LIST}: {@code u8 count | (u8 nlen | name | 48 hash)*}.
     */
    public List<Peer> peers() {
        if (!ok() || body.length < 1) {
            return null;
        }
        int nrec = body[0] & 0xFF;
        int off = 1;
        List<Peer> out = new ArrayList<>(nrec);
        for (int i = 0; i < nrec; i++) {
            if (off >= body.length) {
                return null;
            }
            int nlen = body[off++] & 0xFF;
            if (nlen > SeConstants.PEER_NAME_MAX || off + nlen + SeConstants.PEER_HASH_LEN > body.length) {
                return null;
            }
            String name = new String(body, off, nlen, StandardCharsets.US_ASCII);
            off += nlen;
            byte[] hash = new byte[SeConstants.PEER_HASH_LEN];
            System.arraycopy(body, off, hash, 0, SeConstants.PEER_HASH_LEN);
            off += SeConstants.PEER_HASH_LEN;
            out.add(new Peer(name, hash));
        }
        if (off != body.length) {
            return null;
        }
        return out;
    }

    public record Peer(String name, byte[] hash) {
        public Peer {
            Objects.requireNonNull(name, "name");
            hash = hash == null ? new byte[0] : SeBytes.copy(hash);
        }
    }
}
