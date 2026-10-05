package fel.cvut.db;

import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(60)
class RecordFetchLockTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap originMap;

    @BeforeEach
    void setUp() {
        originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
    }

    @Test
    void lockFetchRequiresSynchronizationOwnedByIssuer() {
        assertFalse(originMap.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        assertFalse(originMap.lockFetch(HASH_1, HASH_2, PEER_SAE));
        assertTrue(originMap.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_FETCHING_STARTED,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
    }

    @Test
    void fetchingStartedBlocksHigherIssuingSaeUntilStale() {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        assertTrue(originMap.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.NOT_INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), PEER_SAE)
        );
    }
}
