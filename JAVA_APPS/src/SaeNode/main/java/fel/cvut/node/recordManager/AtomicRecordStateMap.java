package fel.cvut.node.recordManager;

import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.db.RecordRetention;

import javax.sql.DataSource;
import java.io.Serializable;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Optional;

/**
 * Thread-safe record-state store backed by SQLite {@code client_record_state}.
 *
 * <p>Lifecycle for a new share: {@link RecordAvailability#RECORD_SYNCHRONIZATION}
 * (may be taken over by higher issuing SAE) → {@link RecordAvailability#RECORD_FETCHING_STARTED}
 * (locked to the issuing SAE; only stale reclaim) → {@link RecordAvailability#RECORD_AVAILABLE}.
 */
public class AtomicRecordStateMap {

    /** Stale reclaim window for synchronization and fetching reservations. */
    static final long RESERVATION_TIMEOUT_MINUTES = 2;

    private final DataSource dataSource;
    private final ClientRecordStateRepository repository;
    private final String parentSaeId;
    private final Duration retention;

    public AtomicRecordStateMap(
            String parentSaeId,
            DataSource dataSource,
            ClientRecordStateRepository repository
    ) {
        this(parentSaeId, dataSource, repository, RecordRetention.retentionFromEnvironment());
    }

    public AtomicRecordStateMap(
            String parentSaeId,
            DataSource dataSource,
            ClientRecordStateRepository repository,
            Duration retention
    ) {
        validateSaeId(parentSaeId);
        this.parentSaeId = parentSaeId;
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource must not be null");
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.retention = Objects.requireNonNull(retention, "retention must not be null");
        if (retention.isZero() || retention.isNegative()) {
            throw new IllegalArgumentException("retention must be positive");
        }
    }

    /**
     * Reads metadata for a client-hash pair. Expired rows are refused (treated as absent).
     */
    public Optional<RecordMetadata> get(String clientHash1, String clientHash2) {
        try (Connection connection = dataSource.getConnection()) {
            Optional<RecordMetadata> found = repository.findByHashes(connection, clientHash1, clientHash2);
            return found.filter(metadata -> !isExpired(metadata.dateOfCreation()));
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to read record state.", ex);
        }
    }

    /**
     * Reserves {@link RecordAvailability#RECORD_SYNCHRONIZATION} when eligibility rules allow.
     *
     * @param clientHeader client header containing key hashes and remote SAE ID
     * @param issuingSaeId SAE ID of the node issuing this reservation
     * @return reservation outcome
     */
    public SynchronizeOutcome synchronize(ClientRecord.ClientHeader clientHeader, String issuingSaeId) {
        Objects.requireNonNull(clientHeader, "clientHeader must not be null");
        String clientHash1 = clientHeader.clientHash1();
        String clientHash2 = clientHeader.clientHash2();
        String saeId = clientHeader.saeId();
        validateSaeId(saeId);
        validateSaeId(issuingSaeId);
        Instant now = Instant.now();
        Instant oldestAllowedReservation = now.minus(RESERVATION_TIMEOUT_MINUTES, ChronoUnit.MINUTES);

        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                Optional<RecordMetadata> existing =
                        repository.findForUpdate(connection, clientHash1, clientHash2);
                SynchronizeOutcome outcome = evaluateSynchronizeEligibility(
                        existing.orElse(null),
                        saeId,
                        issuingSaeId,
                        oldestAllowedReservation
                );

                if (outcome == SynchronizeOutcome.INSERTED) {
                    RecordMetadata metadata =
                            new RecordMetadata(now, RecordAvailability.RECORD_SYNCHRONIZATION, saeId, issuingSaeId);
                    repository.replace(connection, clientHash1, clientHash2, metadata);
                }

                connection.commit();
                return outcome;
            } catch (SQLException | RuntimeException ex) {
                rollback(connection, ex);
                if (ex instanceof SQLException sqlEx) {
                    throw new IllegalStateException("Failed to synchronize record state.", sqlEx);
                }
                throw ex;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to synchronize record state.", ex);
        }
    }

    /**
     * Promotes {@link RecordAvailability#RECORD_SYNCHRONIZATION} owned by {@code issuingSaeId}
     * to {@link RecordAvailability#RECORD_FETCHING_STARTED}. Fails if the row is missing,
     * not synchronizing, or owned by another issuer.
     */
    public boolean lockFetch(String clientHash1, String clientHash2, String issuingSaeId) {
        validateSaeId(issuingSaeId);
        Instant now = Instant.now();
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                Optional<RecordMetadata> existing =
                        repository.findForUpdate(connection, clientHash1, clientHash2);
                if (existing.isEmpty()) {
                    connection.commit();
                    return false;
                }
                RecordMetadata current = existing.get();
                if (current.recordAvailability() != RecordAvailability.RECORD_SYNCHRONIZATION
                        || !Objects.equals(current.issuingSaeId(), issuingSaeId)) {
                    connection.commit();
                    return false;
                }
                repository.replace(
                        connection,
                        clientHash1,
                        clientHash2,
                        new RecordMetadata(
                                now,
                                RecordAvailability.RECORD_FETCHING_STARTED,
                                current.saeId(),
                                issuingSaeId
                        )
                );
                connection.commit();
                return true;
            } catch (SQLException ex) {
                rollback(connection, ex);
                throw new IllegalStateException("Failed to lock fetch for record state.", ex);
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to lock fetch for record state.", ex);
        }
    }

    /**
     * Finishes an exchange by promoting {@link RecordAvailability#RECORD_FETCHING_STARTED}
     * to {@link RecordAvailability#RECORD_AVAILABLE}.
     */
    public boolean finishRecordInsert(String clientHash1, String clientHash2) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                boolean changed = repository.finishIfFetching(connection, clientHash1, clientHash2);
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
        try (Connection connection = dataSource.getConnection()) {
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
        try (Connection connection = dataSource.getConnection()) {
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

    boolean isExpired(Instant dateOfCreation) {
        return dateOfCreation.isBefore(Instant.now().minus(retention));
    }

    private SynchronizeOutcome evaluateSynchronizeEligibility(
            RecordMetadata current,
            String saeId,
            String issuingSaeId,
            Instant oldestAllowedReservation
    ) {
        if (current == null || isExpired(current.dateOfCreation())) {
            return SynchronizeOutcome.INSERTED;
        }

        if (current.recordAvailability() == RecordAvailability.RECORD_AVAILABLE) {
            if (Objects.equals(current.saeId(), saeId)) {
                return SynchronizeOutcome.RECORD_AVAILABLE;
            }
            return SynchronizeOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE;
        }

        boolean staleReservation = current.dateOfCreation().isBefore(oldestAllowedReservation);

        if (current.recordAvailability() == RecordAvailability.RECORD_FETCHING_STARTED) {
            // Fetch lock: only stale reclaim; no higher-SAE / same-issuer overwrite.
            if (staleReservation) {
                return SynchronizeOutcome.INSERTED;
            }
            return SynchronizeOutcome.NOT_INSERTED;
        }

        // RECORD_SYNCHRONIZATION: higher issuer, same issuer, or stale reservation may overwrite.
        boolean higherIssuingSaeId = issuingSaeId != null && isSaeIdHigher(issuingSaeId, parentSaeId);
        boolean sameIssuingSaeId = Objects.equals(current.issuingSaeId(), issuingSaeId);
        if (staleReservation || higherIssuingSaeId || sameIssuingSaeId) {
            return SynchronizeOutcome.INSERTED;
        }

        if (!Objects.equals(current.saeId(), saeId)) {
            return SynchronizeOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE;
        }
        return SynchronizeOutcome.NOT_INSERTED;
    }

    public enum RecordAvailability {
        RECORD_SYNCHRONIZATION,
        RECORD_FETCHING_STARTED,
        RECORD_AVAILABLE
    }

    public enum SynchronizeOutcome {
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
