package fel.cvut.db;

import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.utimaco.HsmAesGcm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(60)
class SharedKeyMaterialTamperTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap stateMap;
    private SharedKeyMaterialStore store;
    private final List<String> payload = List.of("alpha", "beta");

    @BeforeEach
    void setUp() {
        stateMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        store = SaeFixtures.keyStore(SQLITE.origin(), JceAesGcm.mockHsm());
    }

    @Test
    void roundTripReturnsOriginalPayload() throws Exception {
        persistRecord();
        assertEquals(payload, store.readPayload(HASH_1, HASH_2).orElseThrow());
    }

    @Test
    void flippedCiphertextIsRejected() throws Exception {
        persistRecord();
        tamperBytes("ciphertext");
        IOException thrown = assertThrows(IOException.class, () -> store.readPayload(HASH_1, HASH_2));
        assertTrue(thrown.getMessage().contains("Failed to read") || thrown.getCause() != null);
    }

    @Test
    void flippedIvIsRejected() throws Exception {
        persistRecord();
        tamperBytes("gcm_iv");
        assertThrows(IOException.class, () -> store.readPayload(HASH_1, HASH_2));
    }

    @Test
    void sqlCheckRejectsNon128TagBits() throws Exception {
        persistRecord();
        assertThrows(Exception.class, () -> {
            try (Connection connection = SQLITE.origin().getConnection();
                 PreparedStatement statement = connection.prepareStatement(
                         "UPDATE shared_key_material SET gcm_tag_bits = 96 WHERE client_hash1 = ? AND client_hash2 = ?")) {
                statement.setString(1, HASH_1);
                statement.setString(2, HASH_2);
                statement.executeUpdate();
            }
        });
        assertEquals(payload, store.readPayload(HASH_1, HASH_2).orElseThrow());
    }

    @Test
    void sealedBlobRejectsWrongTagBitsBeforeDecrypt() {
        HsmAesGcm.SealedBlob blob = new HsmAesGcm.SealedBlob(
                new byte[32],
                new byte[HsmAesGcm.GCM_IV_LENGTH],
                96,
                JceAesGcm.ALIAS
        );
        assertThrows(IllegalArgumentException.class, blob::verify);
    }

    @Test
    void wrongHsmAliasIsRejected() throws Exception {
        persistRecord();
        try (Connection connection = SQLITE.origin().getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "UPDATE shared_key_material SET hsm_key_alias = 'other-key' WHERE client_hash1 = ? AND client_hash2 = ?")) {
            statement.setString(1, HASH_1);
            statement.setString(2, HASH_2);
            assertEquals(1, statement.executeUpdate());
        }
        assertThrows(IOException.class, () -> store.readPayload(HASH_1, HASH_2));
    }

    private void persistRecord() throws Exception {
        ClientRecord record = SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, payload);
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                stateMap.synchronize(record.getClientHeader(), ORIGIN_SAE)
        );
        store.write(record);
    }

    private void tamperBytes(String column) throws Exception {
        try (Connection connection = SQLITE.origin().getConnection();
             PreparedStatement select = connection.prepareStatement(
                     "SELECT " + column + " FROM shared_key_material WHERE client_hash1 = ? AND client_hash2 = ?")) {
            select.setString(1, HASH_1);
            select.setString(2, HASH_2);
            try (ResultSet resultSet = select.executeQuery()) {
                assertTrue(resultSet.next());
                byte[] original = resultSet.getBytes(1);
                byte[] tampered = JceAesGcm.flipByte(original, 0);
                try (PreparedStatement update = connection.prepareStatement(
                        "UPDATE shared_key_material SET " + column + " = ? WHERE client_hash1 = ? AND client_hash2 = ?")) {
                    update.setBytes(1, tampered);
                    update.setString(2, HASH_1);
                    update.setString(3, HASH_2);
                    assertEquals(1, update.executeUpdate());
                }
            }
        }
    }
}
