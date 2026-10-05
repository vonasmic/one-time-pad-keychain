package fel.cvut.db;

import fel.cvut.utimaco.HsmAesGcm;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

/**
 * JDBC persistence for {@code shared_key_material} rows.
 */
public final class SharedKeyMaterialRepository {

    private static final String UPSERT = """
            INSERT INTO shared_key_material (
                client_hash1, client_hash2,
                ciphertext, gcm_iv, gcm_tag_bits, hsm_key_alias
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (client_hash1, client_hash2) DO UPDATE SET
                ciphertext = EXCLUDED.ciphertext,
                gcm_iv = EXCLUDED.gcm_iv,
                gcm_tag_bits = EXCLUDED.gcm_tag_bits,
                hsm_key_alias = EXCLUDED.hsm_key_alias
            """;

    private static final String SELECT_BY_HASHES = """
            SELECT ciphertext, gcm_iv, gcm_tag_bits, hsm_key_alias
            FROM shared_key_material
            WHERE client_hash1 = ? AND client_hash2 = ?
            """;

    private static final String DELETE_BY_HASHES = """
            DELETE FROM shared_key_material
            WHERE client_hash1 = ? AND client_hash2 = ?
            """;

    public void upsert(
            Connection connection,
            String clientHash1,
            String clientHash2,
            HsmAesGcm.SealedBlob sealed
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(UPSERT)) {
            statement.setString(1, clientHash1);
            statement.setString(2, clientHash2);
            statement.setBytes(3, sealed.ciphertext());
            statement.setBytes(4, sealed.gcmIv());
            statement.setInt(5, sealed.gcmTagBits());
            statement.setString(6, sealed.hsmKeyAlias());
            statement.executeUpdate();
        }
    }

    public Optional<HsmAesGcm.SealedBlob> findByHashes(
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

    public boolean deleteByHashes(
            Connection connection,
            String clientHash1,
            String clientHash2
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(DELETE_BY_HASHES)) {
            statement.setString(1, clientHash1);
            statement.setString(2, clientHash2);
            return statement.executeUpdate() > 0;
        }
    }

    private static HsmAesGcm.SealedBlob mapRow(ResultSet resultSet) throws SQLException {
        return new HsmAesGcm.SealedBlob(
                resultSet.getBytes("ciphertext"),
                resultSet.getBytes("gcm_iv"),
                resultSet.getInt("gcm_tag_bits"),
                resultSet.getString("hsm_key_alias")
        );
    }
}
