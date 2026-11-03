package fel.cvut.node;

import fel.cvut.node.recordManager.AtomicRecordStateMap;

import java.util.Objects;

/**
 * Consistency of a share across its two SAEs: a share is available only when both rows are
 * {@code KEYS_AVAILABLE} with the same token and name each other.
 */
public final class ShareConsistency {

    private ShareConsistency() {
    }

    /**
     * @param local      this SAE's row
     * @param other      the counterpart's row of the pair (its orientation), or {@code null}
     * @param localSaeId this SAE
     */
    public static boolean consistent(
            AtomicRecordStateMap.RecordMetadata local,
            AtomicRecordStateMap.RecordMetadata other,
            String localSaeId
    ) {
        Objects.requireNonNull(local, "local");
        if (other == null) {
            return false;
        }
        return local.recordAvailability() == AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE
                && other.recordAvailability() == AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE
                && local.token().equals(other.token())
                && localSaeId.equals(other.saeId())
                && Objects.equals(local.issuingSaeId(), other.issuingSaeId());
    }

    static String describe(AtomicRecordStateMap.RecordMetadata other) {
        if (other == null) {
            return "no row";
        }
        return "row " + other.recordAvailability() + " issued by SAE " + other.issuingSaeId()
                + " for SAE " + other.saeId() + (other.token() == null ? "" : ", other token");
    }
}
