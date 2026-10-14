package fel.cvut.db;

import fel.cvut.node.recordManager.AtomicRecordStateMap;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Optional;

/**
 * JDBC persistence for {@code client_record_state} rows.
 */
public final class ClientRecordStateRepository {

    private static final String SELECT_FOR_UPDATE = """
            SELECT date_of_creation, record_availability, sae_id, issuing_sae_id, pad_plain_len
            FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ?
            """;

    private static final String SELECT_FOR_READ = """
            SELECT date_of_creation, record_availability, sae_id, issuing_sae_id, pad_plain_len
            FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ?
            """;

    private static final String DELETE_BY_HASHES = """
            DELETE FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ?
            RETURNING date_of_creation, record_availability, sae_id, issuing_sae_id, pad_plain_len
            """;

    private static final String DELETE_IF_ISSUING_SAE_MATCHES = """
            DELETE FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ? AND issuing_sae_id = ?
            RETURNING date_of_creation, record_availability, sae_id, issuing_sae_id, pad_plain_len
            """;

    private static final String UPSERT = """
            INSERT INTO client_record_state (
                client_hash1, client_hash2, date_of_creation,
                record_availability, sae_id, issuing_sae_id, pad_plain_len
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (client_hash1, client_hash2) DO UPDATE SET
                date_of_creation = EXCLUDED.date_of_creation,
                record_availability = EXCLUDED.record_availability,
                sae_id = EXCLUDED.sae_id,
                issuing_sae_id = EXCLUDED.issuing_sae_id,
                pad_plain_len = EXCLUDED.pad_plain_len
            """;

    private static final String FINISH_IF_FETCHING = """
            UPDATE client_record_state
            SET record_availability = ?,
                date_of_creation = ?
            WHERE client_hash1 = ? AND client_hash2 = ?
              AND record_availability = 'RECORD_FETCHING_STARTED'
            """;

    private static final String MARK_ORIGIN_PROVISIONED = """
            UPDATE client_record_state
            SET record_availability = ?
            WHERE client_hash1 = ? AND client_hash2 = ?
              AND record_availability = 'RECORD_SHARED'
            """;

    private static final String DELETE_OLDER_THAN = """
            DELETE FROM client_record_state
            WHERE date_of_creation < ?
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

    /**
     * Reads and locks the row for update within the caller's IMMEDIATE transaction.
     * SQLite has no row-level {@code FOR UPDATE}; exclusive write locking comes from
     * {@link fel.cvut.db.DB}'s {@code BEGIN IMMEDIATE} transaction mode.
     */
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
            statement.setString(3, metadata.dateOfCreation().toString());
            statement.setString(4, metadata.recordAvailability().name());
            statement.setString(5, metadata.saeId());
            statement.setString(6, metadata.issuingSaeId());
            statement.setInt(7, metadata.padPlainLen());
            statement.executeUpdate();
        }
    }

    public boolean finishIfFetching(
            Connection connection,
            String clientHash1,
            String clientHash2,
            Instant now
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(FINISH_IF_FETCHING)) {
            statement.setString(1, AtomicRecordStateMap.RecordAvailability.RECORD_SHARED.name());
            statement.setString(2, now.toString());
            statement.setString(3, clientHash1);
            statement.setString(4, clientHash2);
            return statement.executeUpdate() > 0;
        }
    }

    /**
     * Sets {@code ORIGIN_PROVISIONED} only from {@code RECORD_SHARED}.
     */
    public boolean markOriginProvisionedIfShared(
            Connection connection,
            String clientHash1,
            String clientHash2
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(MARK_ORIGIN_PROVISIONED)) {
            statement.setString(1, AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED.name());
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

    public int deleteOlderThan(Connection connection, Instant cutoff) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(DELETE_OLDER_THAN)) {
            statement.setString(1, cutoff.toString());
            return statement.executeUpdate();
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
        Instant dateOfCreation = Instant.parse(resultSet.getString("date_of_creation"));
        AtomicRecordStateMap.RecordAvailability availability =
                AtomicRecordStateMap.RecordAvailability.valueOf(resultSet.getString("record_availability"));
        String saeId = resultSet.getString("sae_id");
        String issuingSaeId = resultSet.getString("issuing_sae_id");
        int padPlainLen = resultSet.getInt("pad_plain_len");
        return new AtomicRecordStateMap.RecordMetadata(
                dateOfCreation, availability, saeId, issuingSaeId, padPlainLen);
    }
}
