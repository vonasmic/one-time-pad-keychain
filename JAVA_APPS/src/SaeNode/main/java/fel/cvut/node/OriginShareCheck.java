package fel.cvut.node;

import fel.cvut.node.recordManager.AtomicRecordStateMap;

import java.time.Instant;
import java.util.Objects;

/**
 * Whether the origin row allows sending a stored share to the peer device.
 * {@code null} origin metadata means the read succeeded and the row is absent.
 * {@code RECORD_SHARED} is an incomplete setup and is deleted once stale.
 * Delivery requires {@code ORIGIN_PROVISIONED} on the origin; the caller also
 * requires it on the local row.
 */
public final class OriginShareCheck {

    public static final String UNREACHABLE_MESSAGE =
            "Origin SAE is unreachable. Keys were not sent to the device.";
    public static final String IN_PROGRESS_MESSAGE =
            "Origin SAE has not finished provision. Keys were not sent to the device.";
    public static final String DELETED_MESSAGE =
            "Origin provision did not finish. Shared keys were deleted. Retry.";

    public enum Decision {
        /** Origin row is {@code ORIGIN_PROVISIONED}. The stored half may be sent. */
        PROVISIONED,
        /** Incomplete setup is still inside the reservation timeout. Send nothing. */
        IN_PROGRESS,
        /** Origin row is missing or the incomplete setup is stale. Delete both rows. */
        DELETE_BOTH
    }

    private OriginShareCheck() {
    }

    /**
     * @param origin origin metadata, or {@code null} when the read succeeded and the row is absent
     * @param now    clock used for the reservation timeout
     */
    public static Decision decide(AtomicRecordStateMap.RecordMetadata origin, Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        if (origin == null) {
            return Decision.DELETE_BOTH;
        }
        if (origin.recordAvailability() == AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED) {
            return Decision.PROVISIONED;
        }
        boolean stale = AtomicRecordStateMap.isReservationStale(origin.dateOfCreation(), now);
        return stale ? Decision.DELETE_BOTH : Decision.IN_PROGRESS;
    }
}
