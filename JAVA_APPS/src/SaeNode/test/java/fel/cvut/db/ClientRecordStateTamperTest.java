package fel.cvut.db;

import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.sql.Connection;
import java.sql.PreparedStatement;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(60)
class ClientRecordStateTamperTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap stateMap;

    @BeforeEach
    void setUp() {
        stateMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
    }

    @Test
    void tamperedMetadataIsStillReadable() throws Exception {
        insertAvailable();
        try (Connection connection = SQLITE.origin().getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "UPDATE client_record_state SET sae_id = 'sae-9', issuing_sae_id = 'sae-9' "
                             + "WHERE client_hash1 = ? AND client_hash2 = ?")) {
            statement.setString(1, HASH_1);
            statement.setString(2, HASH_2);
            assertEquals(1, statement.executeUpdate());
        }

        AtomicRecordStateMap.RecordMetadata metadata = stateMap.get(HASH_1, HASH_2).orElseThrow();
        assertEquals("sae-9", metadata.saeId());
        assertEquals("sae-9", metadata.issuingSaeId());
    }

    @Test
    void tamperedPeerIdBlocksNewInsertAsDenialOfService() throws Exception {
        insertAvailable();
        try (Connection connection = SQLITE.origin().getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "UPDATE client_record_state SET sae_id = 'sae-9' WHERE client_hash1 = ? AND client_hash2 = ?")) {
            statement.setString(1, HASH_1);
            statement.setString(2, HASH_2);
            assertEquals(1, statement.executeUpdate());
        }

        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE,
                stateMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        assertTrue(stateMap.get(HASH_1, HASH_2).isPresent());
    }

    @Test
    void flippedAvailabilityStillReturnsTheRow() throws Exception {
        insertAvailable();
        try (Connection connection = SQLITE.origin().getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "UPDATE client_record_state SET record_availability = 'RECORD_SYNCHRONIZATION' "
                             + "WHERE client_hash1 = ? AND client_hash2 = ?")) {
            statement.setString(1, HASH_1);
            statement.setString(2, HASH_2);
            assertEquals(1, statement.executeUpdate());
        }

        AtomicRecordStateMap.RecordMetadata metadata = stateMap.get(HASH_1, HASH_2).orElseThrow();
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SYNCHRONIZATION,
                metadata.recordAvailability()
        );
    }

    private void insertAvailable() {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                stateMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        assertTrue(stateMap.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
        assertTrue(stateMap.finishRecordInsert(HASH_1, HASH_2));
    }
}
