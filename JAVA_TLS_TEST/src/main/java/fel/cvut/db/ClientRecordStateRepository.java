package fel.cvut.db;

import fel.cvut.node.recordManager.AtomicRecordStateMap;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

/**
 * JDBC persistence for {@code client_record_state} rows.
 */
public final class ClientRecordStateRepository {

    private static final String SELECT_FOR_UPDATE = """
            SELECT date_of_creation, record_availability, sae_id, issuing_sae_id
            FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ?
            FOR UPDATE
            """;

    private static final String SELECT_FOR_READ = """
            SELECT date_of_creation, record_availability, sae_id, issuing_sae_id
            FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ?
            """;

    private static final String DELETE_BY_HASHES = """
            DELETE FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ?
            RETURNING date_of_creation, record_availability, sae_id, issuing_sae_id
            """;

    private static final String DELETE_IF_ISSUING_SAE_MATCHES = """
            DELETE FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ? AND issuing_sae_id = ?
            RETURNING date_of_creation, record_availability, sae_id, issuing_sae_id
            """;

    private static final String UPSERT = """
            INSERT INTO client_record_state (
                client_hash1, client_hash2, date_of_creation,
                record_availability, sae_id, issuing_sae_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (client_hash1, client_hash2) DO UPDATE SET
                date_of_creation = EXCLUDED.date_of_creation,
                record_availability = EXCLUDED.record_availability,
                sae_id = EXCLUDED.sae_id,
                issuing_sae_id = EXCLUDED.issuing_sae_id
            """;

    private static final String UPDATE_AVAILABILITY = """
            UPDATE client_record_state
            SET record_availability = ?
            WHERE client_hash1 = ? AND client_hash2 = ?
              AND record_availability = 'RECORD_IN_PROGRESS'
            """;

    public Optional<AtomicRecordStateMap.RecordMetadata> findByHashes(
            Connection connection,
            String clientHash1,
            String clientHash2
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SELECT_FOR_READ)) {
            statement.setString(1, clientHash1);
            statement.setString(2, clientHash2);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }
                return Optional.of(mapRow(resultSet));
            }
        }
    }

    public Optional<AtomicRecordStateMap.RecordMetadata> findForUpdate(
            Connection connection,
            String clientHash1,
            String clientHash2
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SELECT_FOR_UPDATE)) {
            statement.setString(1, clientHash1);
            statement.setString(2, clientHash2);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }
                return Optional.of(mapRow(resultSet));
            }
        }
    }

    public void replace(
            Connection connection,
            String clientHash1,
            String clientHash2,
            AtomicRecordStateMap.RecordMetadata metadata
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(UPSERT)) {
            statement.setString(1, clientHash1);
            statement.setString(2, clientHash2);
            statement.setTimestamp(3, Timestamp.from(metadata.dateOfCreation()));
            statement.setString(4, metadata.recordAvailability().name());
            statement.setString(5, metadata.saeId());
            statement.setString(6, metadata.issuingSaeId());
            statement.executeUpdate();
        }
    }

    public boolean finishIfInProgress(
            Connection connection,
            String clientHash1,
            String clientHash2
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(UPDATE_AVAILABILITY)) {
            statement.setString(1, AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE.name());
            statement.setString(2, clientHash1);
            statement.setString(3, clientHash2);
            return statement.executeUpdate() > 0;
        }
    }

    public Optional<AtomicRecordStateMap.RecordMetadata> deleteByHashes(
            Connection connection,
            String clientHash1,
            String clientHash2
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(DELETE_BY_HASHES)) {
            statement.setString(1, clientHash1);
            statement.setString(2, clientHash2);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }
                return Optional.of(mapRow(resultSet));
            }
        }
    }

    public Optional<AtomicRecordStateMap.RecordMetadata> deleteIfIssuingSae(
            Connection connection,
            String clientHash1,
            String clientHash2,
            String issuingSaeId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(DELETE_IF_ISSUING_SAE_MATCHES)) {
            statement.setString(1, clientHash1);
            statement.setString(2, clientHash2);
            statement.setString(3, issuingSaeId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }
                return Optional.of(mapRow(resultSet));
            }
        }
    }

    private static AtomicRecordStateMap.RecordMetadata mapRow(ResultSet resultSet) throws SQLException {
        Instant dateOfCreation = resultSet.getTimestamp("date_of_creation").toInstant();
        AtomicRecordStateMap.RecordAvailability availability =
                AtomicRecordStateMap.RecordAvailability.valueOf(resultSet.getString("record_availability"));
        String saeId = resultSet.getString("sae_id");
        String issuingSaeId = resultSet.getString("issuing_sae_id");
        return new AtomicRecordStateMap.RecordMetadata(dateOfCreation, availability, saeId, issuingSaeId);
    }
}
