package fel.cvut.node;

import fel.cvut.node.recordManager.AtomicRecordStateMap;

import java.time.Instant;
import java.util.Objects;

/**
 * What a node that already stores {@code RECORD_AVAILABLE} material does after reading
 * the issuing SAE's row. {@code null} origin metadata means the read succeeded and the
 * row is absent. A failed read is not a decision: the caller must not delete.
 */
public final class OriginShareCheck {

    public static final String UNREACHABLE_MESSAGE =
            "Origin SAE is unreachable. Keys were not sent to the device.";
    public static final String IN_PROGRESS_MESSAGE =
            "Origin SAE has not finished provision. Keys were not sent to the device.";
    public static final String DELETED_MESSAGE =
            "Origin provision did not finish. Shared keys were deleted. Retry.";

    public enum Decision {
        /** Origin device acked the downlink. The stored half may be sent. */
        PROVISIONED,
        /** Origin upload or fetch is still inside the reservation timeout. Send nothing. */
        IN_PROGRESS,
        /** Origin row is missing or stale. Delete the peer row and the origin row. */
        DELETE_BOTH,
        /**
         * Origin holds a fresh {@code RECORD_SYNCHRONIZATION}. A new attempt already
         * reserved the origin. Delete only the leftover peer material.
         */
        DELETE_LOCAL
    }

    private OriginShareCheck() {
    }

    public static Decision decide(AtomicRecordStateMap.RecordMetadata origin, Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        if (origin == null) {
            return Decision.DELETE_BOTH;
        }
        boolean stale = AtomicRecordStateMap.isReservationStale(origin.dateOfCreation(), now);
        return switch (origin.recordAvailability()) {
            case RECORD_PROVISIONED -> Decision.PROVISIONED;
            case RECORD_AVAILABLE, RECORD_FETCHING_STARTED ->
                    stale ? Decision.DELETE_BOTH : Decision.IN_PROGRESS;
            case RECORD_SYNCHRONIZATION ->
                    stale ? Decision.DELETE_BOTH : Decision.DELETE_LOCAL;
        };
    }
}
