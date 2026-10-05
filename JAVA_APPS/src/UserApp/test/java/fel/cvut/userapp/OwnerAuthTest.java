package fel.cvut.userapp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class OwnerAuthTest {

    @Test
    void ownerSetAsciiStatuses() {
        assertInstanceOf(ChipInit.OwnerSetResult.AlreadyEnrolled.class,
                OwnerAuth.classifyOwnerSetDone("refused"));
        assertInstanceOf(ChipInit.OwnerSetResult.Ok.class,
                OwnerAuth.classifyOwnerSetDone("ok"));
        assertInstanceOf(ChipInit.OwnerSetResult.Failed.class,
                OwnerAuth.classifyOwnerSetDone("failed"));
        assertInstanceOf(ChipInit.OwnerSetResult.Failed.class,
                OwnerAuth.classifyOwnerSetDone(null));
    }
}
