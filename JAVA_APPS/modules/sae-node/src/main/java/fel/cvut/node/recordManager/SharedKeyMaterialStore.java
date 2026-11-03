package fel.cvut.node.recordManager;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.db.RecordRetention;
import fel.cvut.db.SharedKeyMaterialRepository;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.utimaco.HsmAesGcm;

import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Persists shared QKD key material encrypted with HSM AES-256-GCM into {@code shared_key_material}.
 */
public final class SharedKeyMaterialStore {

    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() {
    };

    private final DataSource dataSource;
    private final SharedKeyMaterialRepository repository;
    private final ClientRecordStateRepository recordStateRepository;
    private final HsmAesGcm hsmAesGcm;
    private final ObjectMapper objectMapper;
    private final PairLockRegistry registry;
    private final Duration retention;

    public SharedKeyMaterialStore(
            DataSource dataSource,
            SharedKeyMaterialRepository repository,
            HsmAesGcm hsmAesGcm,
            ObjectMapper objectMapper,
            PairLockRegistry registry
    ) {
        this(
                dataSource,
                repository,
                new ClientRecordStateRepository(),
                hsmAesGcm,
                objectMapper,
                registry,
                RecordRetention.retentionFromEnvironment()
        );
    }

    public SharedKeyMaterialStore(
            DataSource dataSource,
            SharedKeyMaterialRepository repository,
            ClientRecordStateRepository recordStateRepository,
            HsmAesGcm hsmAesGcm,
            ObjectMapper objectMapper,
            PairLockRegistry registry,
            Duration retention
    ) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource must not be null");
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.recordStateRepository = Objects.requireNonNull(
                recordStateRepository, "recordStateRepository must not be null");
        this.hsmAesGcm = Objects.requireNonNull(hsmAesGcm, "hsmAesGcm must not be null");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.registry = Objects.requireNonNull(registry, "registry must not be null");
        this.retention = Objects.requireNonNull(retention, "retention must not be null");
        if (retention.isZero() || retention.isNegative()) {
            throw new IllegalArgumentException("retention must be positive");
        }
    }

    /**
     * Peer half of a new share: encrypts the key material (outside the lease), then writes the
     * pair's row as {@code KEYS_AVAILABLE} (counterpart and issuer {@code issuingSaeId}, token
     * {@code token}) and its key material in one transaction under the lease {@code token},
     * replacing any older row of the pair.
     *
     * @throws PairLockLostException {@code token} does not hold the pair lease of
     *                               {@code issuingSaeId}; nothing is written
     */
    public void writeKeysAvailable(ClientRecord clientRecord, String issuingSaeId, String token)
            throws IOException, PairLockLostException {
        Objects.requireNonNull(issuingSaeId, "issuingSaeId must not be null");
        ClientRecord.ClientHeader header = clientRecord.getClientHeader();
        HsmAesGcm.SealedBlob sealed;
        try {
            sealed = hsmAesGcm.encrypt(objectMapper.writeValueAsBytes(clientRecord.getPayload()));
        } catch (Exception ex) {
            throw new IOException("Failed to encrypt shared key material", ex);
        }
        AtomicRecordStateMap.RecordMetadata metadata = new AtomicRecordStateMap.RecordMetadata(
                Instant.now(), AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE,
                issuingSaeId, issuingSaeId, token, header.padPlainLen());
        try {
            registry.withLease(PairKey.of(header.clientHash1(), header.clientHash2()), issuingSaeId, token,
                    connection -> {
                        recordStateRepository.upsert(connection, header.clientHash1(), header.clientHash2(), metadata);
                        repository.upsert(connection, header.clientHash1(), header.clientHash2(), sealed);
                        return null;
                    });
        } catch (SQLException ex) {
            throw new IOException("Failed to persist encrypted shared key material", ex);
        }
    }

    public Optional<List<String>> readPayload(
            String clientHash1,
            String clientHash2
    ) throws IOException {
        try {
            Optional<HsmAesGcm.SealedBlob> sealed;
            try (Connection connection = dataSource.getConnection()) {
                Optional<AtomicRecordStateMap.RecordMetadata> state =
                        recordStateRepository.findByHashes(connection, clientHash1, clientHash2);
                if (state.isEmpty() || isExpired(state.get().dateOfCreation())) {
                    // Refuse serving expired or orphaned material (DB replay defense).
                    return Optional.empty();
                }
                sealed = repository.findByHashes(connection, clientHash1, clientHash2);
            }
            if (sealed.isEmpty()) {
                return Optional.empty();
            }
            byte[] plaintext = hsmAesGcm.decrypt(sealed.get());
            List<String> payload = objectMapper.readValue(plaintext, STRING_LIST);
            return Optional.of(payload);
        } catch (Exception ex) {
            if (ex instanceof IOException ioException) {
                throw ioException;
            }
            throw new IOException("Failed to read encrypted shared key material", ex);
        }
    }

    private boolean isExpired(java.time.Instant dateOfCreation) {
        return dateOfCreation.isBefore(java.time.Instant.now().minus(retention));
    }
}
