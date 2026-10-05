package fel.cvut.node.recordManager;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.db.RecordRetention;
import fel.cvut.db.SharedKeyMaterialRepository;
import fel.cvut.utimaco.HsmAesGcm;

import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
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
    private final Duration retention;

    public SharedKeyMaterialStore(
            DataSource dataSource,
            SharedKeyMaterialRepository repository,
            HsmAesGcm hsmAesGcm,
            ObjectMapper objectMapper
    ) {
        this(
                dataSource,
                repository,
                new ClientRecordStateRepository(),
                hsmAesGcm,
                objectMapper,
                RecordRetention.retentionFromEnvironment()
        );
    }

    public SharedKeyMaterialStore(
            DataSource dataSource,
            SharedKeyMaterialRepository repository,
            ClientRecordStateRepository recordStateRepository,
            HsmAesGcm hsmAesGcm,
            ObjectMapper objectMapper,
            Duration retention
    ) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource must not be null");
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.recordStateRepository = Objects.requireNonNull(
                recordStateRepository, "recordStateRepository must not be null");
        this.hsmAesGcm = Objects.requireNonNull(hsmAesGcm, "hsmAesGcm must not be null");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.retention = Objects.requireNonNull(retention, "retention must not be null");
        if (retention.isZero() || retention.isNegative()) {
            throw new IllegalArgumentException("retention must be positive");
        }
    }

    public void write(ClientRecord clientRecord) throws IOException {
        ClientRecord.ClientHeader header = clientRecord.getClientHeader();
        try {
            byte[] plaintext = objectMapper.writeValueAsBytes(clientRecord.getPayload());
            HsmAesGcm.SealedBlob sealed = hsmAesGcm.encrypt(plaintext);
            try (Connection connection = dataSource.getConnection()) {
                repository.upsert(connection, header.clientHash1(), header.clientHash2(), sealed);
            }
        } catch (Exception ex) {
            if (ex instanceof IOException ioException) {
                throw ioException;
            }
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

    public boolean remove(String clientHash1, String clientHash2) throws IOException {
        try (Connection connection = dataSource.getConnection()) {
            return repository.deleteByHashes(connection, clientHash1, clientHash2);
        } catch (Exception ex) {
            throw new IOException("Failed to delete shared key material", ex);
        }
    }

    private boolean isExpired(java.time.Instant dateOfCreation) {
        return dateOfCreation.isBefore(java.time.Instant.now().minus(retention));
    }
}
