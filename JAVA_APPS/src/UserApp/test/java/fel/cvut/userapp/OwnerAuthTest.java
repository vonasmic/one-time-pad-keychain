package fel.cvut.userapp;

import fel.cvut.se.SeConstants;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

class OwnerAuthTest {

    @Test
    void ownerSetAsciiStatuses() {
        assertInstanceOf(ChipInit.OwnerSetResult.AlreadyEnrolled.class,
                OwnerAuth.classifyOwnerSetDone("refused"));
        assertInstanceOf(ChipInit.OwnerSetResult.Ok.class,
                OwnerAuth.classifyOwnerSetDone("ok"));
        ChipInit.OwnerSetResult failed = OwnerAuth.classifyOwnerSetDone("failed");
        assertInstanceOf(ChipInit.OwnerSetResult.Failed.class, failed);
        assertEquals("failed", ((ChipInit.OwnerSetResult.Failed) failed).detail());
        ChipInit.OwnerSetResult id = OwnerAuth.classifyOwnerSetDone("failed id");
        assertInstanceOf(ChipInit.OwnerSetResult.Failed.class, id);
        assertEquals("failed id", ((ChipInit.OwnerSetResult.Failed) id).detail());
        assertInstanceOf(ChipInit.OwnerSetResult.Failed.class,
                OwnerAuth.classifyOwnerSetDone(null));
    }

    @Test
    void clientCsrIgnoresTruncatedHex() {
        assertNull(OwnerAuth.csrPubOrNull("failed"));
        assertNull(OwnerAuth.csrPubOrNull("abc"));
        byte[] oneFrame = OwnerAuth.csrPubOrNull("aa".repeat(512));
        assertEquals(512, oneFrame.length);
        String full = "ab".repeat(SeConstants.MLDSA_PUB_LEN);
        byte[] pub = OwnerAuth.csrPubOrNull(full.substring(0, 96) + "\n" + full.substring(96));
        assertEquals(SeConstants.MLDSA_PUB_LEN, pub.length);
    }
}
