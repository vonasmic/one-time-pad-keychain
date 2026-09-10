package fel.cvut.userapp;

import fel.cvut.tls.NodeTls;
import fel.cvut.usb.SeUsbLink;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Unsigned first-wins {@code OWNER SET} USB blob, and unsigned MANAGE TLS
 * application data (no ML-DSA). ENCRYPT/DECRYPT stay mTLS elsewhere.
 */
final class OwnerAuth {

    static final int CMD_KEM_INIT = 1;
    static final int CMD_KEYGEN = 2;
    static final int CMD_PEER_ADD = 3;
    static final int CMD_PEER_REMOVE = 4;
    static final int CMD_CREDS_SAE = 5;
    static final int CMD_CREDS_DEVICE = 6;
    static final int CMD_OWNER_REPLACE = 7;

    static final int PIN_MIN = 4;
    static final int PIN_MAX = 8;
    static final int PW_MIN = 8;
    static final int PW_MAX = 64;
    static final int OWNER_SPKI_LEN = 1312;
    static final int OK = 0;

    record ManageResult(int status, String msg) {
        boolean ok() {
            return status == OK;
        }
    }

    private OwnerAuth() {
    }

    static byte[] pinBytes(String pin) {
        Objects.requireNonNull(pin, "pin");
        if (pin.length() < PIN_MIN || pin.length() > PIN_MAX) {
            throw new IllegalArgumentException("PIN must be " + PIN_MIN + "–" + PIN_MAX + " digits");
        }
        for (int i = 0; i < pin.length(); i++) {
            char c = pin.charAt(i);
            if (c < '0' || c > '9') {
                throw new IllegalArgumentException("PIN must be digits 0-9");
            }
        }
        return pin.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] ownerSetFrame(byte[] password, byte[] spki, byte[] cert, byte[] key, byte[] saeCa) {
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(spki, "spki");
        byte[] c = cert == null ? new byte[0] : cert;
        byte[] k = key == null ? new byte[0] : key;
        byte[] ca = saeCa == null ? new byte[0] : saeCa;
        if (password.length < PW_MIN || password.length > PW_MAX) {
            throw new IllegalArgumentException("reset password must be " + PW_MIN + "–" + PW_MAX + " ASCII");
        }
        if (spki.length == 0 || spki.length > OWNER_SPKI_LEN) {
            throw new IllegalArgumentException("owner SPKI length");
        }
        if ((c.length == 0) != (k.length == 0)) {
            throw new IllegalArgumentException("device cert and key must both be present or both omitted");
        }
        ByteBuffer buf = ByteBuffer.allocate(
                        1 + password.length + 2 + spki.length + 2 + c.length + 2 + k.length + 2 + ca.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        buf.put((byte) password.length);
        buf.put(password);
        buf.putShort((short) spki.length);
        buf.put(spki);
        buf.putShort((short) c.length);
        buf.put(c);
        buf.putShort((short) k.length);
        buf.put(k);
        buf.putShort((short) ca.length);
        buf.put(ca);
        return buf.array();
    }

    static byte[] peerAddBody(String name, byte[] hash48) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(hash48, "hash");
        byte[] nb = name.getBytes(StandardCharsets.US_ASCII);
        if (nb.length < 1 || nb.length > 16 || hash48.length != 48) {
            throw new IllegalArgumentException("PEER ADD body");
        }
        ByteArrayOutputStream extra = new ByteArrayOutputStream(1 + nb.length + 48);
        extra.write(nb.length);
        extra.writeBytes(nb);
        extra.writeBytes(hash48);
        return extra.toByteArray();
    }

    static byte[] peerRemoveBody(String name) {
        Objects.requireNonNull(name, "name");
        byte[] nb = name.getBytes(StandardCharsets.US_ASCII);
        if (nb.length < 1 || nb.length > 16) {
            throw new IllegalArgumentException("PEER REMOVE body");
        }
        ByteArrayOutputStream extra = new ByteArrayOutputStream(1 + nb.length);
        extra.write(nb.length);
        extra.writeBytes(nb);
        return extra.toByteArray();
    }

    static byte[] ownerReplaceBody(byte[] oldPassword, byte[] newPassword, byte[] spki) {
        Objects.requireNonNull(oldPassword, "oldPassword");
        Objects.requireNonNull(newPassword, "newPassword");
        Objects.requireNonNull(spki, "spki");
        if (oldPassword.length < PW_MIN || oldPassword.length > PW_MAX
                || newPassword.length < PW_MIN || newPassword.length > PW_MAX) {
            throw new IllegalArgumentException("reset password must be " + PW_MIN + "–" + PW_MAX + " ASCII");
        }
        if (spki.length == 0 || spki.length > OWNER_SPKI_LEN) {
            throw new IllegalArgumentException("owner SPKI length");
        }
        ByteBuffer buf = ByteBuffer.allocate(1 + oldPassword.length + 1 + newPassword.length + 2 + spki.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        buf.put((byte) oldPassword.length);
        buf.put(oldPassword);
        buf.put((byte) newPassword.length);
        buf.put(newPassword);
        buf.putShort((short) spki.length);
        buf.put(spki);
        return buf.array();
    }

    static byte[] manageRequest(int cmd, byte[] pin, byte[] body) {
        byte[] p = pin == null ? new byte[0] : pin;
        byte[] b = body == null ? new byte[0] : body;
        ByteBuffer buf = ByteBuffer.allocate(1 + 1 + p.length + 2 + b.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        buf.put((byte) cmd);
        buf.put((byte) p.length);
        buf.put(p);
        buf.putShort((short) b.length);
        buf.put(b);
        return buf.array();
    }

    static String completeOwnerSet(SeUsbLink usb, byte[] password, byte[] spki, byte[] cert, byte[] key,
                                   byte[] saeCa, long idleMs, long maxMs) throws IOException {
        usb.writeRaw(ownerSetFrame(password, spki, cert, key, saeCa));
        return usb.readConsole(idleMs, maxMs);
    }

    /**
     * Owner-pinned TLS (no device client cert). Streams one unsigned command, then reads
     * {@code u8 status | u16le msg_len | msg}.
     */
    static ManageResult manage(SeUsbLink usb, SSLContext ctx, int cmd, String pin, byte[] body)
            throws Exception {
        Objects.requireNonNull(usb, "usb");
        Objects.requireNonNull(ctx, "ctx");
        byte[] pinB = (pin == null || pin.isEmpty()) ? new byte[0] : pinBytes(pin);
        try {
            usb.armTls("MANAGE");
            try (SSLSocket ssl = NodeTls.wrapServer(ctx, usb.asSocket(), NodeTls.TlsProfile.PURE_PQC, false)) {
                ssl.startHandshake();
                ssl.getOutputStream().write(manageRequest(cmd, pinB, body));
                ssl.getOutputStream().flush();
                return readResult(ssl.getInputStream());
            }
        } finally {
            usb.resetConsole();
        }
    }

    private static ManageResult readResult(InputStream in) throws IOException {
        int status = in.read();
        int lo = in.read();
        int hi = in.read();
        if (status < 0 || lo < 0 || hi < 0) {
            throw new EOFException("MANAGE reply truncated");
        }
        int msgLen = (lo & 0xff) | ((hi & 0xff) << 8);
        byte[] msg = in.readNBytes(msgLen);
        if (msg.length != msgLen) {
            throw new EOFException("MANAGE message truncated");
        }
        return new ManageResult(status, new String(msg, StandardCharsets.US_ASCII));
    }
}
