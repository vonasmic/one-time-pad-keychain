package fel.cvut.db;

import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaePostgresExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.sql.Connection;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(60)
class RecordRetentionTest {

    private static final String OLD_IN_PROGRESS_HASH = "c".repeat(64);
    private static final String KEPT_HASH = "d".repeat(64);
    private static final Duration RETENTION = Duration.ofDays(14);

    @RegisterExtension
    static final SaePostgresExtension POSTGRES = new SaePostgresExtension();

    private final ClientRecordStateRepository states = new ClientRecordStateRepository();
    private final SharedKeyMaterialRepository keys = new SharedKeyMaterialRepository();

    @Test
    void purgeDeletesRowsOlderThanRetentionAndKeepsNewer() throws Exception {
        Instant now = Instant.now();
        insertState(HASH_1, HASH_2, now.minus(15, ChronoUnit.DAYS),
                AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);
        insertState(KEPT_HASH, HASH_2, now.minus(1, ChronoUnit.DAYS),
                AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);

        assertEquals(1, RecordRetention.purgeExpired(POSTGRES.origin(), RETENTION));
        try (Connection connection = POSTGRES.origin().getConnection()) {
            assertTrue(states.findByHashes(connection, HASH_1, HASH_2).isEmpty());
            assertTrue(states.findByHashes(connection, KEPT_HASH, HASH_2).isPresent());
        }
        assertEquals(1, SaeFixtures.countRecords(POSTGRES.origin()));
    }

    @Test
    void purgeDeletesBothAvailabilityStates() throws Exception {
        Instant old = Instant.now().minus(20, ChronoUnit.DAYS);
        insertState(HASH_1, HASH_2, old, AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE);
        insertState(OLD_IN_PROGRESS_HASH, HASH_2, old,
                AtomicRecordStateMap.RecordAvailability.RECORD_IN_PROGRESS);

        assertEquals(2, RecordRetention.purgeExpired(POSTGRES.origin(), RETENTION));
        assertEquals(0, SaeFixtures.countRecords(POSTGRES.origin()));
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

        assertEquals(1, RecordRetention.purgeExpired(POSTGRES.origin(), RETENTION));
        try (Connection connection = POSTGRES.origin().getConnection()) {
            assertTrue(keys.findByHashes(connection, HASH_1, HASH_2).isEmpty());
            assertTrue(keys.findByHashes(connection, KEPT_HASH, HASH_2).isPresent());
        }
        assertEquals(1, SaeFixtures.countKeyMaterial(POSTGRES.origin()));
        assertEquals(1, SaeFixtures.countRecords(POSTGRES.origin()));
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

    private void insertState(
            String hash1,
            String hash2,
            Instant created,
            AtomicRecordStateMap.RecordAvailability availability
    ) throws Exception {
        try (Connection connection = POSTGRES.origin().getConnection()) {
            states.replace(connection, hash1, hash2, new AtomicRecordStateMap.RecordMetadata(
                    created, availability, ORIGIN_SAE, ORIGIN_SAE));
        }
    }

    private void insertMaterial(String hash1, String hash2) throws Exception {
        try (Connection connection = POSTGRES.origin().getConnection()) {
            keys.upsert(connection, hash1, hash2, JceAesGcm.encrypt("pad".getBytes()));
        }
    }
}
