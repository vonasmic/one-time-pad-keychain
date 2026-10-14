package fel.cvut.unit.node;

import fel.cvut.node.*;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("unit")
class OriginShareCheckTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant FRESH = Instant.parse("2026-01-01T00:04:59Z");
    private static final Instant STALE = Instant.parse("2026-01-01T00:05:01Z");

    @Test
    void missingOriginDeletesBoth() {
        assertEquals(OriginShareCheck.Decision.DELETE_BOTH, OriginShareCheck.decide(null, FRESH));
    }

    @Test
    void provisionedAllowsDelivery() {
        assertEquals(
                OriginShareCheck.Decision.PROVISIONED,
                OriginShareCheck.decide(row(AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED, T0), STALE));
    }

    @Test
    void freshSharedIsInProgress() {
        assertEquals(
                OriginShareCheck.Decision.IN_PROGRESS,
                OriginShareCheck.decide(row(AtomicRecordStateMap.RecordAvailability.RECORD_SHARED, T0), FRESH));
    }

    @Test
    void staleSharedDeletesBoth() {
        assertEquals(
                OriginShareCheck.Decision.DELETE_BOTH,
                OriginShareCheck.decide(row(AtomicRecordStateMap.RecordAvailability.RECORD_SHARED, T0), STALE));
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
    void freshSynchronizationIsInProgress() {
        assertEquals(
                OriginShareCheck.Decision.IN_PROGRESS,
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
    void exactlyFiveMinutesIsNotStale() {
        Instant exactly = Instant.parse("2026-01-01T00:05:00Z");
        assertEquals(
                OriginShareCheck.Decision.IN_PROGRESS,
                OriginShareCheck.decide(row(AtomicRecordStateMap.RecordAvailability.RECORD_SHARED, T0), exactly));
    }

    private static AtomicRecordStateMap.RecordMetadata row(
            AtomicRecordStateMap.RecordAvailability availability,
            Instant created
    ) {
        return new AtomicRecordStateMap.RecordMetadata(created, availability, "sae-2", "sae-1", 35);
    }
}
