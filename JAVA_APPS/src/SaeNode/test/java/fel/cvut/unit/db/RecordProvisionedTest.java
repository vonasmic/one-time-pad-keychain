package fel.cvut.unit.db;

import fel.cvut.db.*;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.Tag;

import java.time.Instant;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(60)
@Tag("unit")
class RecordProvisionedTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap originMap;

    @BeforeEach
    void setUp() {
        originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
    }

    @Test
    void finishRecordInsertRefreshesTimestamp() throws Exception {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        Instant reserved = originMap.get(HASH_1, HASH_2).orElseThrow().dateOfCreation();
        Thread.sleep(5);
        assertTrue(originMap.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
        assertTrue(originMap.finishRecordInsert(HASH_1, HASH_2));
        AtomicRecordStateMap.RecordMetadata available = originMap.get(HASH_1, HASH_2).orElseThrow();
        assertEquals(AtomicRecordStateMap.RecordAvailability.RECORD_SHARED, available.recordAvailability());
        assertTrue(available.dateOfCreation().isAfter(reserved));
    }

    @Test
    void markOriginProvisionedOnlyFromShared() {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        assertFalse(originMap.markOriginProvisioned(HASH_1, HASH_2));
        assertTrue(originMap.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
        assertFalse(originMap.markOriginProvisioned(HASH_1, HASH_2));
        assertTrue(originMap.finishRecordInsert(HASH_1, HASH_2));
        assertTrue(originMap.markOriginProvisioned(HASH_1, HASH_2));
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.ORIGIN_PROVISIONED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
    }
}
