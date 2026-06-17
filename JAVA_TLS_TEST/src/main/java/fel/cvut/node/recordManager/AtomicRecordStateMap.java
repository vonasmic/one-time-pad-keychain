package fel.cvut.node.recordManager;

import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.db.DB;

import java.io.Serializable;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Thread-safe record-state store backed by PostgreSQL {@code client_record_state}.
 */
public class AtomicRecordStateMap {

    private static final long IN_PROGRESS_TIMEOUT_MINUTES = 30;
    private final ClientRecordStateRepository repository = new ClientRecordStateRepository();
    private final String parentSaeId;

    public AtomicRecordStateMap(String parentSaeId) {
        validateSaeId(parentSaeId);
        this.parentSaeId = parentSaeId;
    }

    /**
     * Reads metadata for a client-hash pair.
     */
    public Optional<RecordMetadata> get(String clientHash1, String clientHash2) {
        try (Connection connection = DB.connect()) {
            return repository.findByHashes(connection, clientHash1, clientHash2);
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to read record state.", ex);
        }
    }

    /**
     * Starts record insertion by creating or replacing an in-progress state when one of the allowed
     * insertion rules is satisfied.
     *
     * @param clientHeader client header containing key hashes and remote SAE ID
     * @param issuingSaeId SAE ID of the node issuing this insert (optional for backward compatibility)
     * @return insertion outcome for this reservation attempt
     */
    public StartRecordInsertOutcome startRecordInsert(ClientRecord.ClientHeader clientHeader, String issuingSaeId) {
        Objects.requireNonNull(clientHeader, "clientHeader must not be null");
        String clientHash1 = clientHeader.clientHash1();
        String clientHash2 = clientHeader.clientHash2();
        String saeId = clientHeader.saeId();
        validateSaeId(saeId);
        validateSaeId(issuingSaeId);
        Instant now = Instant.now();
        Instant oldestAllowedInProgress = now.minus(IN_PROGRESS_TIMEOUT_MINUTES, ChronoUnit.MINUTES);

        try (Connection connection = DB.connect()) {
            connection.setAutoCommit(false);
            try {
                Optional<RecordMetadata> existing =
                        repository.findForUpdate(connection, clientHash1, clientHash2);
                StartRecordInsertOutcome outcome = evaluateInsertEligibility(
                        existing.orElse(null),
                        saeId,
                        issuingSaeId,
                        now,
                        oldestAllowedInProgress
                );

                if (outcome == StartRecordInsertOutcome.INSERTED) {
                    RecordMetadata metadata =
                            new RecordMetadata(now, RecordAvailability.RECORD_IN_PROGRESS, saeId, issuingSaeId);
                    repository.replace(connection, clientHash1, clientHash2, metadata);
                }

                connection.commit();
                return outcome;
            } catch (SQLException | RuntimeException ex) {
                rollback(connection, ex);
                if (ex instanceof SQLException sqlEx) {
                    throw new IllegalStateException("Failed to start record insert.", sqlEx);
                }
                throw ex;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to start record insert.", ex);
        }
    }

    /**
     * Finishes an existing insertion by promoting in-progress state to available.
     */
    public boolean finishRecordInsert(String clientHash1, String clientHash2) {
        try (Connection connection = DB.connect()) {
            connection.setAutoCommit(false);
            try {
                boolean changed = repository.finishIfInProgress(connection, clientHash1, clientHash2);
                connection.commit();
                return changed;
            } catch (SQLException ex) {
                rollback(connection, ex);
                throw new IllegalStateException("Failed to finish record insert.", ex);
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to finish record insert.", ex);
        }
    }

    public Optional<RecordMetadata> tryDelete(String clientHash1, String clientHash2, String issuingSaeId) {
        validateSaeId(issuingSaeId);
        try (Connection connection = DB.connect()) {
            connection.setAutoCommit(false);
            try {
                Optional<RecordMetadata> removed =
                        repository.deleteIfIssuingSae(connection, clientHash1, clientHash2, issuingSaeId);
                connection.commit();
                return removed;
            } catch (SQLException ex) {
                rollback(connection, ex);
                throw new IllegalStateException("Failed to delete record state.", ex);
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to delete record state.", ex);
        }
    }

    public Optional<RecordMetadata> forceDelete(String clientHash1, String clientHash2) {
        try (Connection connection = DB.connect()) {
            connection.setAutoCommit(false);
            try {
                Optional<RecordMetadata> removed =
                        repository.deleteByHashes(connection, clientHash1, clientHash2);
                connection.commit();
                return removed;
            } catch (SQLException ex) {
                rollback(connection, ex);
                throw new IllegalStateException("Failed to force-delete record state.", ex);
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to force-delete record state.", ex);
        }
    }

    public String parentSaeId() {
        return parentSaeId;
    }

    private StartRecordInsertOutcome evaluateInsertEligibility(
            RecordMetadata current,
            String saeId,
            String issuingSaeId,
            Instant now,
            Instant oldestAllowedInProgress
    ) {
        // Rule 1: missing key means no reservation exists yet, so insert immediately.
        if (current == null) {
            return StartRecordInsertOutcome.INSERTED;
        }

        // Nothing to do for non in-progress records.
        if (current.recordAvailability() != RecordAvailability.RECORD_IN_PROGRESS) {
            if (Objects.equals(current.saeId(), saeId)
                    && current.recordAvailability() == RecordAvailability.RECORD_AVAILABLE) {
                return StartRecordInsertOutcome.RECORD_AVAILABLE;
            }
            if (!Objects.equals(current.saeId(), saeId)) {
                return StartRecordInsertOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE;
            }
            return StartRecordInsertOutcome.NOT_INSERTED;
        }

        // Rule 2 + Rule 3 + Rule 4:
        // - stale in-progress reservation (older than timeout) can be reclaimed
        // - higher issuing SAE ID can take over from lower parent SAE ID while in progress
        // - same issuing SAE ID can retry/overwrite its own in-progress reservation
        boolean staleInProgress = current.dateOfCreation().isBefore(oldestAllowedInProgress);
        boolean higherIssuingSaeId = issuingSaeId != null && isSaeIdHigher(issuingSaeId, parentSaeId);
        boolean sameIssuingSaeId = Objects.equals(current.issuingSaeId(), issuingSaeId);
        if (staleInProgress || higherIssuingSaeId || sameIssuingSaeId) {
            return StartRecordInsertOutcome.INSERTED;
        }

        if (!Objects.equals(current.saeId(), saeId)) {
            return StartRecordInsertOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE;
        }
        return StartRecordInsertOutcome.NOT_INSERTED;
    }

    public enum RecordAvailability {
        RECORD_IN_PROGRESS,
        RECORD_AVAILABLE
    }

    public enum StartRecordInsertOutcome {
        INSERTED,
        RECORD_AVAILABLE,
        RECORD_SHARED_WITH_DIFFERENT_SAE,
        NOT_INSERTED
    }

    public record RecordMetadata(
            Instant dateOfCreation,
            RecordAvailability recordAvailability,
            String saeId,
            String issuingSaeId
    ) implements Serializable {
        private static final long serialVersionUID = 1L;

        public RecordMetadata {
            Objects.requireNonNull(dateOfCreation, "dateOfCreation must not be null");
            Objects.requireNonNull(recordAvailability, "recordAvailability must not be null");
            validateSaeId(saeId);
            validateSaeId(issuingSaeId);
        }
    }

    public record ClientHashes(String clientHash1, String clientHash2) {
        public ClientHashes {
            validateHash(clientHash1, "clientHash1");
            validateHash(clientHash2, "clientHash2");
        }

        public static ClientHashes of(String clientHash1, String clientHash2) {
            return new ClientHashes(clientHash1, clientHash2);
        }

        private static void validateHash(String hash, String fieldName) {
            if (hash == null || hash.isBlank()) {
                throw new IllegalArgumentException(fieldName + " must not be null or blank");
            }
        }
    }

    private static void validateSaeId(String saeId) {
        if (saeId == null || saeId.isBlank()) {
            throw new IllegalArgumentException("saeId must not be null or blank");
        }
    }

    private static boolean isSaeIdHigher(String saeId, String otherSaeId) {
        try {
            return new BigInteger(saeId).compareTo(new BigInteger(otherSaeId)) > 0;
        } catch (NumberFormatException ex) {
            return saeId.compareTo(otherSaeId) > 0;
        }
    }

    private static void rollback(Connection connection, Throwable original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackEx) {
            original.addSuppressed(rollbackEx);
        }
    }
}
