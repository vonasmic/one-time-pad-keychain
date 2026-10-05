package fel.cvut.db;

import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.sql.Connection;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

@Timeout(60)
class RecordRetentionTest {

    private static final String OLD_IN_PROGRESS_HASH = "c".repeat(64);
    private static final String KEPT_HASH = "d".repeat(64);
    private static final Duration RETENTION = Duration.ofDays(14);

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private final ClientRecordStateRepository states = new ClientRecordStateRepository();
    private final SharedKeyMaterialRepository keys = new SharedKeyMaterialRepository();

    @Test
    void purgeDeletesRowsOlderThanRetentionAndKeepsNewer() throws Exception {
        Instant now = Instant.now();
        insertState(HASH_1, HASH_2, now.minus(15, ChronoUnit.DAYS),
                AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);
        insertState(KEPT_HASH, HASH_2, now.minus(1, ChronoUnit.DAYS),
                AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);

        assertEquals(1, RecordRetention.purgeExpired(SQLITE.origin(), RETENTION));
        try (Connection connection = SQLITE.origin().getConnection()) {
            assertTrue(states.findByHashes(connection, HASH_1, HASH_2).isEmpty());
            assertTrue(states.findByHashes(connection, KEPT_HASH, HASH_2).isPresent());
        }
        assertEquals(1, SaeFixtures.countRecords(SQLITE.origin()));
    }

    @Test
    void purgeDeletesBothAvailabilityStates() throws Exception {
        Instant old = Instant.now().minus(20, ChronoUnit.DAYS);
        insertState(HASH_1, HASH_2, old, AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);
        insertState(OLD_IN_PROGRESS_HASH, HASH_2, old,
                AtomicRecordStateMap.RecordAvailability.RECORD_SYNCHRONIZATION);

        assertEquals(2, RecordRetention.purgeExpired(SQLITE.origin(), RETENTION));
        assertEquals(0, SaeFixtures.countRecords(SQLITE.origin()));
    }

    @Test
    void purgeCascadesSharedKeyMaterialForDeletedParentsOnly() throws Exception {
        Instant now = Instant.now();
        insertState(HASH_1, HASH_2, now.minus(16, ChronoUnit.DAYS),
                AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);
        insertState(KEPT_HASH, HASH_2, now.minus(2, ChronoUnit.DAYS),
                AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);
        insertMaterial(HASH_1, HASH_2);
        insertMaterial(KEPT_HASH, HASH_2);

        assertEquals(1, RecordRetention.purgeExpired(SQLITE.origin(), RETENTION));
        try (Connection connection = SQLITE.origin().getConnection()) {
            assertTrue(keys.findByHashes(connection, HASH_1, HASH_2).isEmpty());
            assertTrue(keys.findByHashes(connection, KEPT_HASH, HASH_2).isPresent());
        }
        assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.origin()));
        assertEquals(1, SaeFixtures.countRecords(SQLITE.origin()));
    }

    @Test
    void parseRetentionDaysDefaultsToFourteenWhenUnsetOrBlank() {
        assertEquals(Duration.ofDays(RecordRetention.DEFAULT_RETENTION_DAYS),
                RecordRetention.parseRetentionDays(null));
        assertEquals(Duration.ofDays(RecordRetention.DEFAULT_RETENTION_DAYS),
                RecordRetention.parseRetentionDays(""));
        assertEquals(Duration.ofDays(RecordRetention.DEFAULT_RETENTION_DAYS),
                RecordRetention.parseRetentionDays("   "));
    }

    @Test
    void parseRetentionDaysAcceptsCustomPositiveValue() {
        assertEquals(Duration.ofDays(7), RecordRetention.parseRetentionDays("7"));
        assertEquals(Duration.ofDays(30), RecordRetention.parseRetentionDays(" 30 "));
    }

    @Test
    void parseRetentionDaysRejectsInvalidValues() {
        for (String value : List.of("0", "-1", "abc", "14.5")) {
            IllegalStateException thrown = assertThrows(
                    IllegalStateException.class,
                    () -> RecordRetention.parseRetentionDays(value),
                    value
            );
            assertTrue(thrown.getMessage().contains("RECORD_RETENTION_DAYS"), thrown.getMessage());
        }
    }

    @Test
    void getRefusesExpiredMetadata() throws Exception {
        Instant old = Instant.now().minus(20, ChronoUnit.DAYS);
        insertState(HASH_1, HASH_2, old, AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);
        AtomicRecordStateMap stateMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        assertTrue(stateMap.get(HASH_1, HASH_2).isEmpty());
        try (Connection connection = SQLITE.origin().getConnection()) {
            assertTrue(states.findByHashes(connection, HASH_1, HASH_2).isPresent());
        }
    }

    @Test
    void synchronizeReclaimsExpiredAvailableRow() throws Exception {
        Instant old = Instant.now().minus(20, ChronoUnit.DAYS);
        insertState(HASH_1, HASH_2, old, AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);
        AtomicRecordStateMap stateMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        ClientRecord.ClientHeader header = SaeFixtures.header(HASH_1, HASH_2, PEER_SAE);

        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                stateMap.synchronize(header, ORIGIN_SAE)
        );
        Optional<AtomicRecordStateMap.RecordMetadata> after = stateMap.get(HASH_1, HASH_2);
        assertTrue(after.isPresent());
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SYNCHRONIZATION,
                after.get().recordAvailability()
        );
        assertFalse(after.get().dateOfCreation().isBefore(Instant.now().minus(1, ChronoUnit.HOURS)));
    }

    @Test
    void readPayloadRefusesExpiredKeyMaterial() throws Exception {
        Instant old = Instant.now().minus(20, ChronoUnit.DAYS);
        insertState(HASH_1, HASH_2, old, AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);
        insertMaterial(HASH_1, HASH_2);
        SharedKeyMaterialStore store = SaeFixtures.keyStore(SQLITE.origin(), JceAesGcm.mockHsm());
        assertTrue(store.readPayload(HASH_1, HASH_2).isEmpty());
        try (Connection connection = SQLITE.origin().getConnection()) {
            assertTrue(keys.findByHashes(connection, HASH_1, HASH_2).isPresent());
        }
    }

    private void insertState(
            String hash1,
            String hash2,
            Instant created,
            AtomicRecordStateMap.RecordAvailability availability
    ) throws Exception {
        try (Connection connection = SQLITE.origin().getConnection()) {
            states.replace(connection, hash1, hash2, new AtomicRecordStateMap.RecordMetadata(
                    created, availability, ORIGIN_SAE, ORIGIN_SAE));
        }
    }

    private void insertMaterial(String hash1, String hash2) throws Exception {
        try (Connection connection = SQLITE.origin().getConnection()) {
            keys.upsert(connection, hash1, hash2, JceAesGcm.encrypt("pad".getBytes()));
        }
    }
}
