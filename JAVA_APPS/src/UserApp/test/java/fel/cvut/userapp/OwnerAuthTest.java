package fel.cvut.userapp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

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
}
