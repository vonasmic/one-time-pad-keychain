package fel.cvut.unit.node;

import fel.cvut.node.ShareConsistency;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordAvailability;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordMetadata;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class ShareConsistencyTest {

    private static final String LOCAL = "sae-2";
    private static final String ISSUER = "sae-1";

    @Test
    void sameTokenNamingEachOtherIsConsistent() {
        assertTrue(ShareConsistency.consistent(row(ISSUER, ISSUER, "t1"), row(LOCAL, ISSUER, "t1"), LOCAL));
    }

    @Test
    void mismatchedTokensAreNotConsistent() {
        assertFalse(ShareConsistency.consistent(row(ISSUER, ISSUER, "t1"), row(LOCAL, ISSUER, "t2"), LOCAL));
    }

    @Test
    void missingCounterpartRowIsNotConsistent() {
        assertFalse(ShareConsistency.consistent(row(ISSUER, ISSUER, "t1"), null, LOCAL));
    }

    @Test
    void counterpartNamingAnotherSaeIsNotConsistent() {
        assertFalse(ShareConsistency.consistent(row(ISSUER, ISSUER, "t1"), row("sae-3", ISSUER, "t1"), LOCAL));
    }

    @Test
    void differentIssuerIsNotConsistent() {
        assertFalse(ShareConsistency.consistent(row(ISSUER, ISSUER, "t1"), row(LOCAL, LOCAL, "t1"), LOCAL));
    }

    @Test
    void localRowIsRequired() {
        assertThrows(NullPointerException.class, () -> ShareConsistency.consistent(null, row(LOCAL, ISSUER, "t"), LOCAL));
    }

    private static RecordMetadata row(String saeId, String issuer, String token) {
        return new RecordMetadata(Instant.now(), RecordAvailability.KEYS_AVAILABLE, saeId, issuer, token, 32);
    }
}
