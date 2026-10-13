package fel.cvut.node;

import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

class OriginShareCheckTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant FRESH = Instant.parse("2026-01-01T00:01:59Z");
    private static final Instant STALE = Instant.parse("2026-01-01T00:02:01Z");

    @Test
    void missingOriginDeletesBoth() {
        assertEquals(OriginShareCheck.Decision.DELETE_BOTH, OriginShareCheck.decide(null, FRESH));
    }

    @Test
    void provisionedAllowsDelivery() {
        assertEquals(
                OriginShareCheck.Decision.PROVISIONED,
                OriginShareCheck.decide(row(AtomicRecordStateMap.RecordAvailability.RECORD_PROVISIONED, T0), STALE));
    }

    @Test
    void freshAvailableIsInProgress() {
        assertEquals(
                OriginShareCheck.Decision.IN_PROGRESS,
                OriginShareCheck.decide(row(AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE, T0), FRESH));
    }

    @Test
    void staleAvailableDeletesBoth() {
        assertEquals(
                OriginShareCheck.Decision.DELETE_BOTH,
                OriginShareCheck.decide(row(AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE, T0), STALE));
    }

    @Test
    void freshFetchingIsInProgress() {
        assertEquals(
                OriginShareCheck.Decision.IN_PROGRESS,
                OriginShareCheck.decide(
                        row(AtomicRecordStateMap.RecordAvailability.RECORD_FETCHING_STARTED, T0), FRESH));
    }

    @Test
    void staleFetchingDeletesBoth() {
        assertEquals(
                OriginShareCheck.Decision.DELETE_BOTH,
                OriginShareCheck.decide(
                        row(AtomicRecordStateMap.RecordAvailability.RECORD_FETCHING_STARTED, T0), STALE));
    }

    @Test
    void freshSynchronizationDeletesLocalOnly() {
        assertEquals(
                OriginShareCheck.Decision.DELETE_LOCAL,
                OriginShareCheck.decide(
                        row(AtomicRecordStateMap.RecordAvailability.RECORD_SYNCHRONIZATION, T0), FRESH));
    }

    @Test
    void staleSynchronizationDeletesBoth() {
        assertEquals(
                OriginShareCheck.Decision.DELETE_BOTH,
                OriginShareCheck.decide(
                        row(AtomicRecordStateMap.RecordAvailability.RECORD_SYNCHRONIZATION, T0), STALE));
    }

    @Test
    void exactlyTwoMinutesIsNotStale() {
        Instant exactly = Instant.parse("2026-01-01T00:02:00Z");
        assertEquals(
                OriginShareCheck.Decision.IN_PROGRESS,
                OriginShareCheck.decide(row(AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE, T0), exactly));
    }

    private static AtomicRecordStateMap.RecordMetadata row(
            AtomicRecordStateMap.RecordAvailability availability,
            Instant created
    ) {
        return new AtomicRecordStateMap.RecordMetadata(created, availability, "sae-2", "sae-1", 35);
    }
}
