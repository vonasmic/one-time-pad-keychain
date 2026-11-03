package fel.cvut.unit.db;

import fel.cvut.db.*;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.Tag;

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
@Tag("unit")
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
        insertState(HASH_1, HASH_2, now.minus(15, ChronoUnit.DAYS));
        insertState(KEPT_HASH, HASH_2, now.minus(1, ChronoUnit.DAYS));

        assertEquals(1, RecordRetention.purgeExpired(SQLITE.origin(), registry(), RETENTION));
        try (Connection connection = SQLITE.origin().getConnection()) {
            assertTrue(states.findByHashes(connection, HASH_1, HASH_2).isEmpty());
            assertTrue(states.findByHashes(connection, KEPT_HASH, HASH_2).isPresent());
        }
        assertEquals(1, SaeFixtures.countRecords(SQLITE.origin()));
    }

    @Test
    void purgeDeletesEveryExpiredRow() throws Exception {
        Instant old = Instant.now().minus(20, ChronoUnit.DAYS);
        insertState(HASH_1, HASH_2, old);
        insertState(OLD_IN_PROGRESS_HASH, HASH_2, old);

        assertEquals(2, RecordRetention.purgeExpired(SQLITE.origin(), registry(), RETENTION));
        assertEquals(0, SaeFixtures.countRecords(SQLITE.origin()));
    }

    @Test
    void purgeSkipsAPairWhoseLockIsHeld() throws Exception {
        Instant old = Instant.now().minus(20, ChronoUnit.DAYS);
        insertState(HASH_1, HASH_2, old);
        insertState(OLD_IN_PROGRESS_HASH, HASH_2, old);
        String token = PairLockRegistry.newToken();
        assertTrue(registry().tryAcquire(PairKey.of(HASH_1, HASH_2), PEER_SAE, token));

        assertEquals(1, RecordRetention.purgeExpired(SQLITE.origin(), registry(), RETENTION));
        try (Connection connection = SQLITE.origin().getConnection()) {
            assertTrue(states.findByHashes(connection, HASH_1, HASH_2).isPresent());
        }
        assertTrue(registry().holds(PairKey.of(HASH_1, HASH_2), token), "the purge must not touch the lease");

        registry().release(PairKey.of(HASH_1, HASH_2), token);
        assertEquals(1, RecordRetention.purgeExpired(SQLITE.origin(), registry(), RETENTION));
        assertEquals(0, SaeFixtures.countRecords(SQLITE.origin()));
    }

    @Test
    void purgeCascadesSharedKeyMaterialForDeletedParentsOnly() throws Exception {
        Instant now = Instant.now();
        insertState(HASH_1, HASH_2, now.minus(16, ChronoUnit.DAYS));
        insertState(KEPT_HASH, HASH_2, now.minus(2, ChronoUnit.DAYS));
        insertMaterial(HASH_1, HASH_2);
        insertMaterial(KEPT_HASH, HASH_2);

        assertEquals(1, RecordRetention.purgeExpired(SQLITE.origin(), registry(), RETENTION));
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
        insertState(HASH_1, HASH_2, old);
        AtomicRecordStateMap stateMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        assertTrue(stateMap.get(HASH_1, HASH_2).isEmpty());
        try (Connection connection = SQLITE.origin().getConnection()) {
            assertTrue(states.findByHashes(connection, HASH_1, HASH_2).isPresent());
        }
    }

    @Test
    void newShareReplacesAnExpiredRowAndItsKeys() throws Exception {
        Instant old = Instant.now().minus(20, ChronoUnit.DAYS);
        insertState(HASH_1, HASH_2, old);
        insertMaterial(HASH_1, HASH_2);
        AtomicRecordStateMap stateMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        String token = PairLockRegistry.newToken();
        assertTrue(registry().tryAcquire(PairKey.of(HASH_1, HASH_2), ORIGIN_SAE, token));

        stateMap.writeOrigin(token, SaeFixtures.header(HASH_1, HASH_2, PEER_SAE));

        Optional<AtomicRecordStateMap.RecordMetadata> after = stateMap.get(HASH_1, HASH_2);
        assertTrue(after.isPresent());
        assertEquals(token, after.get().token());
        assertFalse(after.get().dateOfCreation().isBefore(Instant.now().minus(1, ChronoUnit.HOURS)));
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.origin()));
    }

    @Test
    void readPayloadRefusesExpiredKeyMaterial() throws Exception {
        Instant old = Instant.now().minus(20, ChronoUnit.DAYS);
        insertState(HASH_1, HASH_2, old);
        insertMaterial(HASH_1, HASH_2);
        SharedKeyMaterialStore store = SaeFixtures.keyStore(SQLITE.origin(), JceAesGcm.mockHsm());
        assertTrue(store.readPayload(HASH_1, HASH_2).isEmpty());
        try (Connection connection = SQLITE.origin().getConnection()) {
            assertTrue(keys.findByHashes(connection, HASH_1, HASH_2).isPresent());
        }
    }

    private static PairLockRegistry registry() {
        return SaeFixtures.registry(SQLITE.origin());
    }

    private void insertState(String hash1, String hash2, Instant created) throws Exception {
        SaeFixtures.insertRow(SQLITE.origin(), hash1, hash2, PEER_SAE, PEER_SAE, PairLockRegistry.newToken(), created);
    }

    private void insertMaterial(String hash1, String hash2) throws Exception {
        try (Connection connection = SQLITE.origin().getConnection()) {
            SaeFixtures.seedKeyMaterial(connection, hash1, hash2, JceAesGcm.encrypt("pad".getBytes()));
        }
    }
}
