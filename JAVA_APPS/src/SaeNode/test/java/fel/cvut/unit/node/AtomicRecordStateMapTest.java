package fel.cvut.unit.node;

import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordAvailability;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordMetadata;
import fel.cvut.node.recordManager.AtomicRecordStateMap.SynchronizeOutcome;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Timeout(60)
@Tag("unit")
class AtomicRecordStateMapTest {

    /** Lower than {@link SaeFixtures#ORIGIN_SAE} under the string fallback comparison. */
    private static final String LOWER_SAE = "sae-0";

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private final ClientRecordStateRepository repository = new ClientRecordStateRepository();



    @Test
    void reservationStalenessBoundary() {
        Instant now = Instant.parse("2026-01-01T12:00:00Z");
        long minutes = AtomicRecordStateMap.RESERVATION_TIMEOUT_MINUTES;
        assertFalse(AtomicRecordStateMap.isReservationStale(now.minus(minutes, ChronoUnit.MINUTES), now));
        assertTrue(AtomicRecordStateMap.isReservationStale(
                now.minus(minutes, ChronoUnit.MINUTES).minusMillis(1), now));
        assertThrows(NullPointerException.class, () -> AtomicRecordStateMap.isReservationStale(null, now));
        assertThrows(NullPointerException.class, () -> AtomicRecordStateMap.isReservationStale(now, null));
    }

    @Test
    void fullLifecycleSynchronizeLockFinishProvisionDelete() {
        AtomicRecordStateMap map = map();
        assertTrue(map.get(HASH_1, HASH_2).isEmpty());

        assertEquals(SynchronizeOutcome.INSERTED, map.synchronize(header(PEER_SAE), ORIGIN_SAE));
        RecordMetadata synced = map.get(HASH_1, HASH_2).orElseThrow();
        assertEquals(RecordAvailability.RECORD_SYNCHRONIZATION, synced.recordAvailability());
        assertEquals(PEER_SAE, synced.saeId());
        assertEquals(ORIGIN_SAE, synced.issuingSaeId());
        assertEquals(SaeFixtures.padPlain(), synced.padPlainLen());

        assertFalse(map.lockFetch(HASH_1, HASH_2, OTHER_SAE), "only the issuing SAE may lock");
        assertFalse(map.finishRecordInsert(HASH_1, HASH_2), "not fetching yet");
        assertTrue(map.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
        assertEquals(RecordAvailability.RECORD_FETCHING_STARTED, map.get(HASH_1, HASH_2).orElseThrow().recordAvailability());
        assertFalse(map.lockFetch(HASH_1, HASH_2, ORIGIN_SAE), "already locked");

        assertEquals(SynchronizeOutcome.NOT_INSERTED, map.synchronize(header(PEER_SAE), OTHER_SAE),
                "a fresh fetch lock cannot be taken over, even by a higher issuer");

        assertFalse(map.markOriginProvisioned(HASH_1, HASH_2), "needs RECORD_SHARED first");
        assertTrue(map.finishRecordInsert(HASH_1, HASH_2));
        assertEquals(RecordAvailability.RECORD_SHARED, map.get(HASH_1, HASH_2).orElseThrow().recordAvailability());
        assertEquals(SynchronizeOutcome.NOT_INSERTED, map.synchronize(header(PEER_SAE), ORIGIN_SAE));
        assertEquals(SynchronizeOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE,
                map.synchronize(header(OTHER_SAE), ORIGIN_SAE));

        assertTrue(map.markOriginProvisioned(HASH_1, HASH_2));
        assertEquals(RecordAvailability.ORIGIN_PROVISIONED, map.get(HASH_1, HASH_2).orElseThrow().recordAvailability());
        assertEquals(SynchronizeOutcome.ORIGIN_PROVISIONED, map.synchronize(header(PEER_SAE), ORIGIN_SAE));
        assertEquals(SynchronizeOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE,
                map.synchronize(header(OTHER_SAE), ORIGIN_SAE));

        assertTrue(map.tryDelete(HASH_1, HASH_2, OTHER_SAE).isEmpty(), "wrong issuer must not delete");
        assertTrue(map.tryDelete(HASH_1, HASH_2, ORIGIN_SAE).isPresent());
        assertTrue(map.get(HASH_1, HASH_2).isEmpty());
    }

    @Test
    void synchronizationRowOverwriteRules() {
        AtomicRecordStateMap map = map();
        assertEquals(SynchronizeOutcome.INSERTED, map.synchronize(header(PEER_SAE), ORIGIN_SAE));

        assertEquals(SynchronizeOutcome.INSERTED, map.synchronize(header(PEER_SAE), ORIGIN_SAE),
                "same issuer may refresh its own reservation");
        assertEquals(SynchronizeOutcome.NOT_INSERTED, map.synchronize(header(PEER_SAE), LOWER_SAE),
                "lower issuer, same target SAE");
        assertEquals(SynchronizeOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE,
                map.synchronize(header(OTHER_SAE), LOWER_SAE));
        assertEquals(ORIGIN_SAE, map.get(HASH_1, HASH_2).orElseThrow().issuingSaeId());

        assertEquals(SynchronizeOutcome.INSERTED, map.synchronize(header(OTHER_SAE), OTHER_SAE),
                "higher issuer than the parent takes over");
        RecordMetadata now = map.get(HASH_1, HASH_2).orElseThrow();
        assertEquals(OTHER_SAE, now.issuingSaeId());
        assertEquals(OTHER_SAE, now.saeId());
    }

    @Test
    void numericSaeIdsCompareNumerically() {
        AtomicRecordStateMap map = new AtomicRecordStateMap("9", SQLITE.origin(), repository, Duration.ofDays(14));
        assertEquals(SynchronizeOutcome.INSERTED, map.synchronize(header(PEER_SAE), "5"));
        assertEquals(SynchronizeOutcome.INSERTED, map.synchronize(header(PEER_SAE), "10"),
                "10 > 9 numerically even though \"10\" < \"9\" as strings");
        assertEquals("10", map.get(HASH_1, HASH_2).orElseThrow().issuingSaeId());
    }

    @Test
    void staleFetchLockAndStaleSharedRowCanBeReclaimed() throws Exception {
        AtomicRecordStateMap map = map();
        Instant stale = Instant.now().minus(AtomicRecordStateMap.RESERVATION_TIMEOUT_MINUTES + 1, ChronoUnit.MINUTES);
        insert(stale, RecordAvailability.RECORD_FETCHING_STARTED, PEER_SAE, ORIGIN_SAE);
        assertEquals(SynchronizeOutcome.INSERTED, map.synchronize(header(OTHER_SAE), LOWER_SAE));
        assertEquals(RecordAvailability.RECORD_SYNCHRONIZATION, map.get(HASH_1, HASH_2).orElseThrow().recordAvailability());
    }

    @Test
    void staleSynchronizationRowCanBeTakenByAnyIssuer() throws Exception {
        AtomicRecordStateMap map = map();
        Instant stale = Instant.now().minus(AtomicRecordStateMap.RESERVATION_TIMEOUT_MINUTES + 1, ChronoUnit.MINUTES);
        insert(stale, RecordAvailability.RECORD_SYNCHRONIZATION, PEER_SAE, ORIGIN_SAE);
        assertEquals(SynchronizeOutcome.INSERTED, map.synchronize(header(OTHER_SAE), LOWER_SAE));
        assertEquals(LOWER_SAE, map.get(HASH_1, HASH_2).orElseThrow().issuingSaeId());
    }


    @Test
    void forceDeleteRemovesRegardlessOfIssuer() {
        AtomicRecordStateMap map = map();
        map.synchronize(header(PEER_SAE), ORIGIN_SAE);
        RecordMetadata removed = map.forceDelete(HASH_1, HASH_2).orElseThrow();
        assertEquals(PEER_SAE, removed.saeId());
        assertTrue(map.forceDelete(HASH_1, HASH_2).isEmpty());
        assertFalse(map.markOriginProvisioned(HASH_1, HASH_2));
        assertFalse(map.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
    }

    @Test
    void databaseFailuresAreWrappedAsIllegalState() throws Exception {
        DataSource broken = mock(DataSource.class);
        SQLException cause = new SQLException("db down");
        when(broken.getConnection()).thenThrow(cause);
        AtomicRecordStateMap map = new AtomicRecordStateMap(ORIGIN_SAE, broken, repository, Duration.ofDays(14));

        assertWrapped(cause, "Failed to read record state.", () -> map.get(HASH_1, HASH_2));
        assertWrapped(cause, "Failed to synchronize record state.", () -> map.synchronize(header(PEER_SAE), ORIGIN_SAE));
        assertWrapped(cause, "Failed to lock fetch for record state.", () -> map.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
        assertWrapped(cause, "Failed to finish record insert.", () -> map.finishRecordInsert(HASH_1, HASH_2));
        assertWrapped(cause, "Failed to mark record provisioned.", () -> map.markOriginProvisioned(HASH_1, HASH_2));
        assertWrapped(cause, "Failed to delete record state.", () -> map.tryDelete(HASH_1, HASH_2, ORIGIN_SAE));
        assertWrapped(cause, "Failed to force-delete record state.", () -> map.forceDelete(HASH_1, HASH_2));
    }

    @Test
    void repositoryFailureInsideTransactionRollsBackAndWraps() throws Exception {
        ClientRecordStateRepository failing = mock(ClientRecordStateRepository.class);
        SQLException cause = new SQLException("constraint");
        when(failing.findForUpdate(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString())).thenThrow(cause);
        AtomicRecordStateMap map = new AtomicRecordStateMap(ORIGIN_SAE, SQLITE.origin(), failing, Duration.ofDays(14));
        assertWrapped(cause, "Failed to synchronize record state.", () -> map.synchronize(header(PEER_SAE), ORIGIN_SAE));
        assertWrapped(cause, "Failed to lock fetch for record state.", () -> map.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
    }

    private static void assertWrapped(SQLException cause, String message, Runnable call) {
        IllegalStateException ex = assertThrows(IllegalStateException.class, call::run);
        assertEquals(message, ex.getMessage());
        assertInstanceOf(SQLException.class, ex.getCause());
        assertEquals(cause, ex.getCause());
    }

    private AtomicRecordStateMap map() {
        return SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
    }

    private static fel.cvut.node.recordManager.ClientRecord.ClientHeader header(String targetSae) {
        return SaeFixtures.header(HASH_1, HASH_2, targetSae);
    }

    private void insert(Instant created, RecordAvailability availability, String sae, String issuer) throws Exception {
        try (Connection connection = SQLITE.origin().getConnection()) {
            repository.replace(connection, HASH_1, HASH_2,
                    new RecordMetadata(created, availability, sae, issuer, SaeFixtures.padPlain()));
        }
    }
}