package fel.cvut.node.recordManager;

import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.db.RecordRetention;
import fel.cvut.db.SharedKeyMaterialRepository;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;

import javax.sql.DataSource;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Record-state store backed by SQLite {@code client_record_state}.
 *
 * <p>A row exists only as {@link RecordAvailability#KEYS_AVAILABLE}: it is written by an
 * operation holding the pair lock on both SAEs and carries that operation's token, the issuing
 * SAE and the counterpart SAE. A share is usable only when both SAEs hold a row with the same
 * token (checked over RMI when the share is used). Every write runs through
 * {@link PairLockRegistry#withLease}.
 */
public class AtomicRecordStateMap {

    private final DataSource dataSource;
    private final ClientRecordStateRepository repository;
    private final SharedKeyMaterialRepository keyMaterialRepository = new SharedKeyMaterialRepository();
    private final PairLockRegistry registry;
    private final String parentSaeId;
    private final Duration retention;

    public AtomicRecordStateMap(
            String parentSaeId,
            DataSource dataSource,
            ClientRecordStateRepository repository,
            PairLockRegistry registry
    ) {
        this(parentSaeId, dataSource, repository, registry, RecordRetention.retentionFromEnvironment());
    }

    public AtomicRecordStateMap(
            String parentSaeId,
            DataSource dataSource,
            ClientRecordStateRepository repository,
            PairLockRegistry registry,
            Duration retention
    ) {
        validateSaeId(parentSaeId);
        this.parentSaeId = parentSaeId;
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource must not be null");
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.registry = Objects.requireNonNull(registry, "registry must not be null");
        this.retention = Objects.requireNonNull(retention, "retention must not be null");
        if (retention.isZero() || retention.isNegative()) {
            throw new IllegalArgumentException("retention must be positive");
        }
    }

    public PairLockRegistry registry() {
        return registry;
    }

    public String parentSaeId() {
        return parentSaeId;
    }

    /** Reads the row of a client-hash pair. Expired rows are refused (treated as absent). */
    public Optional<RecordMetadata> get(String clientHash1, String clientHash2) {
        try (Connection connection = dataSource.getConnection()) {
            Optional<RecordMetadata> found = repository.findByHashes(connection, clientHash1, clientHash2);
            return found.filter(metadata -> !isExpired(metadata.dateOfCreation()));
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to read record state.", ex);
        }
    }

    /**
     * Origin half of a new share: writes {@code KEYS_AVAILABLE} issued by this SAE with the
     * operation token, overwriting any older row of the pair and dropping its key material
     * (the origin keeps none). Runs under the lease {@code token}.
     */
    public void writeOrigin(String token, ClientRecord.ClientHeader header) throws PairLockLostException {
        Objects.requireNonNull(header, "header must not be null");
        validateSaeId(header.saeId());
        RecordMetadata metadata = new RecordMetadata(Instant.now(), RecordAvailability.KEYS_AVAILABLE,
                header.saeId(), parentSaeId, token, header.padPlainLen());
        try {
            registry.withLease(PairKey.of(header.clientHash1(), header.clientHash2()), token, connection -> {
                keyMaterialRepository.deleteByHashes(connection, header.clientHash1(), header.clientHash2());
                repository.upsert(connection, header.clientHash1(), header.clientHash2(), metadata);
                return null;
            });
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to write origin record.", ex);
        }
    }

    /** Local compare-and-delete under this SAE's own lease {@code leaseToken}. */
    public DeleteOutcome deleteIfToken(String leaseToken, String clientHash1, String clientHash2, String rowToken)
            throws PairLockLostException {
        return deleteIfToken(null, leaseToken, clientHash1, clientHash2, rowToken);
    }

    /**
     * Compare-and-delete: removes the pair's row (and by cascade its key material) only when it
     * carries {@code rowToken}, and only while {@code leaseToken} holds the pair lease taken by
     * {@code leaseIssuer} (any issuer when {@code null}).
     */
    public DeleteOutcome deleteIfToken(
            String leaseIssuer, String leaseToken, String clientHash1, String clientHash2, String rowToken)
            throws PairLockLostException {
        Objects.requireNonNull(rowToken, "rowToken must not be null");
        try {
            return registry.withLease(PairKey.of(clientHash1, clientHash2), leaseIssuer, leaseToken, connection -> {
                Optional<RecordMetadata> current = repository.findByHashes(connection, clientHash1, clientHash2);
                if (current.isEmpty()) {
                    return DeleteOutcome.ABSENT;
                }
                return repository.deleteIfToken(connection, clientHash1, clientHash2, rowToken)
                        ? DeleteOutcome.DELETED
                        : DeleteOutcome.TOKEN_MISMATCH;
            });
        } catch (SQLException ex) {
            throw new IllegalStateException("Failed to delete record state.", ex);
        }
    }

    private boolean isExpired(Instant dateOfCreation) {
        return dateOfCreation.isBefore(Instant.now().minus(retention));
    }

    public enum RecordAvailability {
        KEYS_AVAILABLE
    }

    public enum DeleteOutcome {
        DELETED,
        /** No row for the hash pair. */
        ABSENT,
        /** The row carries another token (a newer or an unrelated share); it was kept. */
        TOKEN_MISMATCH
    }

    public record RecordMetadata(
            Instant dateOfCreation,
            RecordAvailability recordAvailability,
            String saeId,
            String issuingSaeId,
            String token,
            int padPlainLen
    ) implements Serializable {
        private static final long serialVersionUID = 3L;

        public RecordMetadata {
            Objects.requireNonNull(dateOfCreation, "dateOfCreation must not be null");
            Objects.requireNonNull(recordAvailability, "recordAvailability must not be null");
            validateSaeId(saeId);
            validateSaeId(issuingSaeId);
            if (token == null || token.isBlank()) {
                throw new IllegalArgumentException("token must not be null or blank");
            }
            if (padPlainLen < 0 || padPlainLen > 0xFFFF) {
                throw new IllegalArgumentException("padPlainLen out of range: " + padPlainLen);
            }
        }
    }

    private static void validateSaeId(String saeId) {
        if (saeId == null || saeId.isBlank()) {
            throw new IllegalArgumentException("saeId must not be null or blank");
        }
    }
}
