package fel.cvut.unit.db;

import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.ShareConsistency;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(60)
@Tag("unit")
class ClientRecordStateTamperTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap stateMap;
    private String token;

    @BeforeEach
    void setUp() throws Exception {
        stateMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        token = PairLockRegistry.newToken();
        assertTrue(stateMap.registry().tryAcquire(PairKey.of(HASH_1, HASH_2), ORIGIN_SAE, token));
        stateMap.writeOrigin(token, SaeFixtures.header(HASH_1, HASH_2, PEER_SAE));
    }

    @Test
    void tamperedMetadataIsStillReadable() throws Exception {
        tamper("UPDATE client_record_state SET sae_id = 'sae-9', issuing_sae_id = 'sae-9' "
                + "WHERE client_hash1 = ? AND client_hash2 = ?");

        AtomicRecordStateMap.RecordMetadata metadata = stateMap.get(HASH_1, HASH_2).orElseThrow();
        assertEquals("sae-9", metadata.saeId());
        assertEquals("sae-9", metadata.issuingSaeId());
    }

    @Test
    void tamperedPeerIdIsReplacedByTheNextShareUnderTheLock() throws Exception {
        tamper("UPDATE client_record_state SET sae_id = 'sae-9' WHERE client_hash1 = ? AND client_hash2 = ?");

        String next = PairLockRegistry.newToken();
        assertTrue(stateMap.registry().tryAcquire(PairKey.of(HASH_1, HASH_2), ORIGIN_SAE, next));
        stateMap.writeOrigin(next, SaeFixtures.header(HASH_1, HASH_2, PEER_SAE));

        AtomicRecordStateMap.RecordMetadata metadata = stateMap.get(HASH_1, HASH_2).orElseThrow();
        assertEquals(PEER_SAE, metadata.saeId());
        assertEquals(next, metadata.token());
    }

    @Test
    void tamperedTokenMakesTheShareInconsistent() throws Exception {
        AtomicRecordStateMap.RecordMetadata peerView = new AtomicRecordStateMap.RecordMetadata(
                java.time.Instant.now(), AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE,
                PEER_SAE, ORIGIN_SAE, token, SaeFixtures.padPlain());
        AtomicRecordStateMap.RecordMetadata originRow = stateMap.get(HASH_1, HASH_2).orElseThrow();
        assertTrue(ShareConsistency.consistent(peerView,
                new AtomicRecordStateMap.RecordMetadata(originRow.dateOfCreation(), originRow.recordAvailability(),
                        originRow.saeId(), originRow.issuingSaeId(), originRow.token(), originRow.padPlainLen()),
                PEER_SAE));

        tamper("UPDATE client_record_state SET lease_token = 'forged' WHERE client_hash1 = ? AND client_hash2 = ?");

        assertFalse(ShareConsistency.consistent(peerView, stateMap.get(HASH_1, HASH_2).orElseThrow(), PEER_SAE));
    }

    @Test
    void schemaRejectsAnyOtherAvailabilityState() {
        assertThrows(SQLException.class, () -> tamper(
                "UPDATE client_record_state SET record_availability = 'RECORD_SYNCHRONIZATION' "
                        + "WHERE client_hash1 = ? AND client_hash2 = ?"));
        assertEquals(AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE,
                stateMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability());
    }

    @Test
    void schemaRejectsAMissingToken() {
        assertThrows(SQLException.class, () -> tamper(
                "UPDATE client_record_state SET lease_token = NULL WHERE client_hash1 = ? AND client_hash2 = ?"));
    }

    private static void tamper(String sql) throws Exception {
        try (Connection connection = SQLITE.origin().getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, HASH_1);
            statement.setString(2, HASH_2);
            assertEquals(1, statement.executeUpdate());
        }
    }
}
