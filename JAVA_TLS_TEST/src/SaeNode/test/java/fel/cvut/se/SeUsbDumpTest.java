package fel.cvut.se;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SeUsbDumpTest {

    @Test
    void roundTripEmptyOk() {
        SeUsbDump dump = new SeUsbDump(SeUsbDump.OK, null);
        SeUsbDump parsed = SeUsbDump.parse(dump.encode());
        assertEquals(SeUsbDump.OK, parsed.status);
        assertEquals(0, parsed.body.length);
        assertTrue(parsed.ok());
    }

    @Test
    void bodyMayStartWithTlsType() {
        byte[] body = {(byte) 0x16, 0x03, 0x03};
        SeUsbDump parsed = SeUsbDump.parse(new SeUsbDump(SeUsbDump.OK, body).encode());
        assertArrayEquals(body, parsed.body);
    }

    @Test
    void otpLeftFourU32() {
        byte[] body = new byte[16];
        System.arraycopy(SeBytes.u32Le(1), 0, body, 0, 4);
        System.arraycopy(SeBytes.u32Le(2), 0, body, 4, 4);
        System.arraycopy(SeBytes.u32Le(3), 0, body, 8, 4);
        System.arraycopy(SeBytes.u32Le(4), 0, body, 12, 4);
        int[] q = new SeUsbDump(SeUsbDump.OK, body).otpLeft();
        assertArrayEquals(new int[] {1, 2, 3, 4}, q);
    }

    @Test
    void peerListEmptyAndOne() {
        assertTrue(new SeUsbDump(SeUsbDump.OK, new byte[] {0}).peers().isEmpty());
        byte[] hash = new byte[SeConstants.PEER_HASH_LEN];
        hash[0] = 9;
        byte[] rec = new byte[1 + 1 + 3 + SeConstants.PEER_HASH_LEN];
        rec[0] = 1;
        rec[1] = 3;
        rec[2] = 'a';
        rec[3] = 'b';
        rec[4] = 'c';
        System.arraycopy(hash, 0, rec, 5, hash.length);
        List<SeUsbDump.Peer> peers = new SeUsbDump(SeUsbDump.OK, rec).peers();
        assertEquals(1, peers.size());
        assertEquals("abc", peers.get(0).name());
        assertArrayEquals(hash, peers.get(0).hash());
        assertNull(new SeUsbDump(SeUsbDump.ERR, rec).peers());
    }
}
