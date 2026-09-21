package fel.cvut.userapp;

import fel.cvut.se.SeConstants;
import fel.cvut.se.SeUsbDump;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

class OwnerAuthTest {

    @Test
    void ownerSetDumpStatuses() {
        assertInstanceOf(ChipInit.OwnerSetResult.AlreadyEnrolled.class,
                OwnerAuth.classifyOwnerSetDone(new SeUsbDump(SeUsbDump.REFUSED, null)));
        assertInstanceOf(ChipInit.OwnerSetResult.Ok.class,
                OwnerAuth.classifyOwnerSetDone(new SeUsbDump(SeUsbDump.OK, null)));
        assertInstanceOf(ChipInit.OwnerSetResult.Failed.class,
                OwnerAuth.classifyOwnerSetDone(new SeUsbDump(SeUsbDump.ERR, null)));
        assertInstanceOf(ChipInit.OwnerSetResult.Failed.class,
                OwnerAuth.classifyOwnerSetDone(null));
    }

    @Test
    void tropicPubPresentVsEmpty() {
        byte[] xy = new byte[SeConstants.ECC_PUB_LEN];
        xy[0] = 0x0a;
        xy[63] = 0x0b;
        assertArrayEquals(xy, new SeUsbDump(SeUsbDump.OK, xy).tropicPub());
        assertNull(new SeUsbDump(SeUsbDump.EMPTY, null).tropicPub());
        assertNull(new SeUsbDump(SeUsbDump.ERR, null).tropicPub());
    }

    @Test
    void clientCsrLen() {
        byte[] pub = new byte[SeConstants.MLDSA_PUB_LEN];
        pub[0] = 1;
        assertArrayEquals(pub, new SeUsbDump(SeUsbDump.OK, pub).clientCsr());
        assertNull(new SeUsbDump(SeUsbDump.ERR, null).clientCsr());
        assertNull(new SeUsbDump(SeUsbDump.OK, new byte[8]).clientCsr());
    }

    @Test
    void clientHashLen() {
        byte[] hash = new byte[SeConstants.CLIENT_HASH_LEN];
        hash[0] = 0x11;
        assertArrayEquals(hash, new SeUsbDump(SeUsbDump.OK, hash).clientHash());
        assertNull(new SeUsbDump(SeUsbDump.ERR, null).clientHash());
        assertNull(new SeUsbDump(SeUsbDump.OK, new byte[8]).clientHash());
    }
}
