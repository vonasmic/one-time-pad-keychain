package fel.cvut.db;

import fel.cvut.node.recordManager.AtomicRecordStateMap;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * JDBC persistence for {@code client_record_state} rows. Every write runs inside a transaction
 * opened by {@link fel.cvut.node.pairlock.PairLockRegistry}, under the lease of the client pair.
 */
public final class ClientRecordStateRepository {

    private static final String COLUMNS =
            "date_of_creation, record_availability, sae_id, issuing_sae_id, lease_token, pad_plain_len";

    private static final String SELECT_BY_HASHES = "SELECT " + COLUMNS + """
             FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ?
            """;

    private static final String UPSERT = """
            INSERT INTO client_record_state (
                client_hash1, client_hash2, date_of_creation,
                record_availability, sae_id, issuing_sae_id, lease_token, pad_plain_len
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (client_hash1, client_hash2) DO UPDATE SET
                date_of_creation = EXCLUDED.date_of_creation,
                record_availability = EXCLUDED.record_availability,
                sae_id = EXCLUDED.sae_id,
                issuing_sae_id = EXCLUDED.issuing_sae_id,
                lease_token = EXCLUDED.lease_token,
                pad_plain_len = EXCLUDED.pad_plain_len
            """;

    private static final String DELETE_IF_TOKEN = """
            DELETE FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ? AND lease_token = ?
            """;

    private static final String SELECT_OLDER_THAN = """
            SELECT client_hash1, client_hash2 FROM client_record_state
            WHERE date_of_creation < ?
            """;

    private static final String DELETE_IF_OLDER_THAN = """
            DELETE FROM client_record_state
            WHERE client_hash1 = ? AND client_hash2 = ? AND date_of_creation < ?
            """;

    public Optional<AtomicRecordStateMap.RecordMetadata> findByHashes(
            Connection connection,
            String clientHash1,
            String clientHash2
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SELECT_BY_HASHES)) {
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

    /** Inserts the row or overwrites the existing row of the same hash pair. */
    public void upsert(
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
            statement.setString(7, metadata.token());
            statement.setInt(8, metadata.padPlainLen());
            statement.executeUpdate();
        }
    }

    /** Compare-and-delete: removes the row only when it still carries {@code rowToken}. */
    public boolean deleteIfToken(
            Connection connection,
            String clientHash1,
            String clientHash2,
            String rowToken
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(DELETE_IF_TOKEN)) {
            statement.setString(1, clientHash1);
            statement.setString(2, clientHash2);
            statement.setString(3, rowToken);
            return statement.executeUpdate() > 0;
        }
    }

    /** Hash pairs (as stored) of rows created before {@code cutoff}. */
    public List<String[]> findOlderThan(Connection connection, Instant cutoff) throws SQLException {
        List<String[]> pairs = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(SELECT_OLDER_THAN)) {
            statement.setString(1, cutoff.toString());
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    pairs.add(new String[]{resultSet.getString(1), resultSet.getString(2)});
                }
            }
        }
        return pairs;
    }

    public boolean deleteIfOlderThan(
            Connection connection,
            String clientHash1,
            String clientHash2,
            Instant cutoff
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(DELETE_IF_OLDER_THAN)) {
            statement.setString(1, clientHash1);
            statement.setString(2, clientHash2);
            statement.setString(3, cutoff.toString());
            return statement.executeUpdate() > 0;
        }
    }

    private static AtomicRecordStateMap.RecordMetadata mapRow(ResultSet resultSet) throws SQLException {
        return new AtomicRecordStateMap.RecordMetadata(
                Instant.parse(resultSet.getString("date_of_creation")),
                AtomicRecordStateMap.RecordAvailability.valueOf(resultSet.getString("record_availability")),
                resultSet.getString("sae_id"),
                resultSet.getString("issuing_sae_id"),
                resultSet.getString("lease_token"),
                resultSet.getInt("pad_plain_len"));
    }
}
