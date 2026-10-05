package fel.cvut.se;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SeManageTest {

    @Test
    void ownerSetGoldenEmptyCa() throws Exception {
        byte[] password = "password".getBytes(StandardCharsets.US_ASCII);
        byte[] spki = filled(SeConstants.MLDSA_PUB_LEN, (byte) 0xAA);
        byte[] wire = SeManage.encodeOwnerSet(password, spki, new byte[0]);

        assertEquals(8, wire[0] & 0xFF);
        assertArrayEquals(password, Arrays.copyOfRange(wire, 1, 9));
        assertEquals(SeConstants.MLDSA_PUB_LEN, (wire[9] & 0xFF) | ((wire[10] & 0xFF) << 8));
        assertArrayEquals(spki, Arrays.copyOfRange(wire, 11, 11 + SeConstants.MLDSA_PUB_LEN));
        int caOff = 11 + SeConstants.MLDSA_PUB_LEN;
        assertEquals(0, (wire[caOff] & 0xFF) | ((wire[caOff + 1] & 0xFF) << 8));
        assertEquals(caOff + 2, wire.length);

        SeManage.OwnerSet decoded = SeManage.decodeOwnerSet(wire);
        assertArrayEquals(password, decoded.password());
        assertArrayEquals(spki, decoded.spki());
        assertEquals(0, decoded.saeCa().length);
    }

    @Test
    void ownerSetNeedMatchesFirmwareFrameNeed() {
        byte[] password = "password".getBytes(StandardCharsets.US_ASCII);
        byte[] spki = filled(4, (byte) 1);
        byte[] ca = {9, 8, 7};
        byte[] wire = SeManage.encodeOwnerSet(password, spki, ca);
        assertEquals(SeManage.NEED_MORE, SeManage.ownerSetNeed(wire, 0));
        assertEquals(SeManage.NEED_MORE, SeManage.ownerSetNeed(wire, 1));
        int caLenOff = 1 + password.length + 2 + spki.length;
        assertEquals(SeManage.NEED_MORE, SeManage.ownerSetNeed(wire, caLenOff + 1));
        assertEquals(wire.length, SeManage.ownerSetNeed(wire, caLenOff + 2));
        assertEquals(wire.length, SeManage.ownerSetNeed(wire, wire.length - 1));
        assertEquals(wire.length, SeManage.ownerSetNeed(wire, wire.length));
        byte[] badPw = wire.clone();
        badPw[0] = 7;
        assertEquals(SeManage.NEED_FAIL, SeManage.ownerSetNeed(badPw, badPw.length));
    }

    @Test
    void ownerSetRejectsEmptySpkiAndOversizeCa() {
        byte[] pw = "password".getBytes(StandardCharsets.US_ASCII);
        assertThrows(IllegalArgumentException.class,
                () -> SeManage.encodeOwnerSet(pw, new byte[0], new byte[0]));
        byte[] spki = filled(8, (byte) 2);
        byte[] ca = new byte[SeConstants.CREDS_DER_MAX + 1];
        assertThrows(IllegalArgumentException.class, () -> SeManage.encodeOwnerSet(pw, spki, ca));
    }

    @Test
    void manageRequestGoldenKemInit() throws Exception {
        byte[] pin = "12345678".getBytes(StandardCharsets.US_ASCII);
        byte[] wire = SeManage.encodeRequest(SeManage.CMD_KEM_INIT, pin, new byte[0]);
        assertArrayEquals(new byte[] {
                SeManage.CMD_KEM_INIT, 8,
                '1', '2', '3', '4', '5', '6', '7', '8',
                0, 0
        }, wire);
        SeManage.Request decoded = SeManage.decodeRequest(wire);
        assertEquals(SeManage.CMD_KEM_INIT, decoded.cmd());
        assertArrayEquals(pin, decoded.pin());
        assertEquals(0, decoded.body().length);
    }

    @Test
    void manageRequestNeedMatchesFirmwareTestK() {
        byte[] req = new byte[8];
        req[0] = (byte) SeManage.CMD_CREDS_SAE;
        req[1] = 0;
        req[2] = 4;
        req[3] = 0;
        req[4] = 1;
        req[5] = 2;
        req[6] = 3;
        req[7] = 4;
        assertEquals(SeManage.NEED_MORE, SeManage.requestNeed(req, 3));
        assertEquals(8, SeManage.requestNeed(req, 8));
    }

    @Test
    void manageReplyRoundTripDoesNotRequireEof() throws Exception {
        SeManage.Reply reply = new SeManage.Reply(SeManage.OK, "INSERT SIGNED CSR ok");
        byte[] wire = SeManage.encodeReply(reply);
        byte[] withTrailing = new byte[wire.length + 4];
        System.arraycopy(wire, 0, withTrailing, 0, wire.length);
        SeManage.Reply decoded = SeManage.readReply(new ByteArrayInputStream(withTrailing));
        assertTrue(decoded.ok());
        assertEquals("INSERT SIGNED CSR ok", decoded.msg());
        SeManage.Reply fail = new SeManage.Reply(SeManage.PIN_FAIL, "PIN fail");
        assertFalse(fail.ok());
        assertEquals(SeManage.PIN_FAIL, SeManage.decodeReply(SeManage.encodeReply(fail)).status());
        assertEquals("PIN fail", fail.describe());
        assertEquals("PIN fail",
                new SeManage.Reply(SeManage.PIN_FAIL, "").describe());
        assertEquals("KEM INIT failed",
                new SeManage.Reply(SeManage.ERR, "KEM INIT failed").describe());
        assertEquals("KEYGEN ok", new SeManage.Reply(SeManage.OK, "KEYGEN ok").describe());
    }

    @Test
    void manageReplyTruncatedThrows() {
        assertThrows(EOFException.class,
                () -> SeManage.decodeReply(new byte[] {0, 2}));
    }

    @Test
    void peerAndReplaceAndCertBodiesRoundTripInsideRequest() throws Exception {
        byte[] hash = filled(SeConstants.PEER_HASH_LEN, (byte) 0x11);
        byte[] add = SeManage.encodePeerAddBody("Alice", hash);
        assertEquals(1 + 5 + 48, add.length);
        assertEquals(5, add[0] & 0xFF);

        byte[] remove = SeManage.encodePeerRemoveBody("Alice");
        assertArrayEquals(new byte[] {5, 'A', 'l', 'i', 'c', 'e'}, remove);

        byte[] spki = filled(32, (byte) 3);
        byte[] oldPw = "oldpass1".getBytes(StandardCharsets.US_ASCII);
        byte[] newPw = "newpass2".getBytes(StandardCharsets.US_ASCII);
        byte[] replace = SeManage.encodeOwnerReplaceBody(oldPw, newPw, spki);
        byte[] req = SeManage.encodeRequest(SeManage.CMD_OWNER_REPLACE, new byte[0], replace);
        SeManage.Request decoded = SeManage.decodeRequest(req);
        assertEquals(SeManage.CMD_OWNER_REPLACE, decoded.cmd());
        assertEquals(0, decoded.pin().length);
        assertArrayEquals(replace, decoded.body());

        byte[] cert = {10, 11, 12, 13};
        byte[] creds = SeManage.encodeDeviceCertBody(cert);
        assertEquals(2 + 4, creds.length);
        assertEquals(4, (creds[0] & 0xFF) | ((creds[1] & 0xFF) << 8));
        assertArrayEquals(new byte[] {1}, SeManage.encodePairingBody(1));
        assertThrows(IllegalArgumentException.class, () -> SeManage.encodePairingBody(0));
    }

    @Test
    void pinAndPasswordAsciiRules() {
        assertTrue(SeManage.pinOk("12345678"));
        assertFalse(SeManage.pinOk("1234567"));
        assertFalse(SeManage.pinOk("12345678\n"));
        assertTrue(SeManage.passwordOk("password".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(SeManage.passwordOk("short".getBytes(StandardCharsets.US_ASCII)));
    }

    private static byte[] filled(int len, byte value) {
        byte[] out = new byte[len];
        Arrays.fill(out, value);
        return out;
    }
}
