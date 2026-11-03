package fel.cvut.unit.node;

import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.AtomicRecordStateMap.DeleteOutcome;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordAvailability;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Timeout(60)
@Tag("unit")
class AtomicRecordStateMapTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap map;
    private PairLockRegistry registry;
    private final PairKey pair = PairKey.of(HASH_1, HASH_2);

    @BeforeEach
    void setUp() {
        map = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        registry = map.registry();
    }

    @Test
    void writeOriginStoresKeysAvailableIssuedByThisSaeWithTheToken() throws Exception {
        String token = lock(ORIGIN_SAE);
        map.writeOrigin(token, SaeFixtures.header(HASH_1, HASH_2, PEER_SAE));

        RecordMetadata row = map.get(HASH_1, HASH_2).orElseThrow();
        assertEquals(RecordAvailability.KEYS_AVAILABLE, row.recordAvailability());
        assertEquals(PEER_SAE, row.saeId());
        assertEquals(ORIGIN_SAE, row.issuingSaeId());
        assertEquals(token, row.token());
        assertEquals(SaeFixtures.padPlain(), row.padPlainLen());
        assertTrue(map.get(HASH_2, HASH_1).isEmpty(), "orientation is exact");
    }

    @Test
    void writeOriginReplacesAnOlderRowAndDropsItsKeyMaterial() throws Exception {
        SaeFixtures.insertRow(SQLITE.origin(), HASH_1, HASH_2, OTHER_SAE, OTHER_SAE, PairLockRegistry.newToken());
        try (Connection connection = SQLITE.origin().getConnection()) {
            SaeFixtures.seedKeyMaterial(connection, HASH_1, HASH_2, fel.cvut.harness.JceAesGcm.encrypt("x".getBytes()));
        }
        String token = lock(ORIGIN_SAE);
        map.writeOrigin(token, SaeFixtures.header(HASH_1, HASH_2, PEER_SAE));

        assertEquals(token, map.get(HASH_1, HASH_2).orElseThrow().token());
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.origin()), "the origin keeps no key material");
    }

    @Test
    void writeOriginWithoutTheLeaseWritesNothing() throws Exception {
        assertThrows(PairLockLostException.class,
                () -> map.writeOrigin(PairLockRegistry.newToken(), SaeFixtures.header(HASH_1, HASH_2, PEER_SAE)));
        String held = lock(PEER_SAE);
        assertThrows(PairLockLostException.class,
                () -> map.writeOrigin(PairLockRegistry.newToken(), SaeFixtures.header(HASH_1, HASH_2, PEER_SAE)));
        assertTrue(registry.holds(pair, held));
        assertEquals(0, SaeFixtures.countRecords(SQLITE.origin()));
    }

    @Test
    void deleteIfTokenComparesTheRowToken() throws Exception {
        String rowToken = PairLockRegistry.newToken();
        SaeFixtures.insertRow(SQLITE.origin(), HASH_1, HASH_2, PEER_SAE, PEER_SAE, rowToken);
        String lease = lock(ORIGIN_SAE);

        assertEquals(DeleteOutcome.TOKEN_MISMATCH,
                map.deleteIfToken(lease, HASH_1, HASH_2, PairLockRegistry.newToken()));
        assertTrue(map.get(HASH_1, HASH_2).isPresent());
        assertEquals(DeleteOutcome.DELETED, map.deleteIfToken(lease, HASH_1, HASH_2, rowToken));
        assertEquals(DeleteOutcome.ABSENT, map.deleteIfToken(lease, HASH_1, HASH_2, rowToken));
    }

    @Test
    void deleteIfTokenNeedsTheLeaseAndOptionallyItsIssuer() throws Exception {
        String rowToken = PairLockRegistry.newToken();
        SaeFixtures.insertRow(SQLITE.origin(), HASH_1, HASH_2, PEER_SAE, PEER_SAE, rowToken);

        assertThrows(PairLockLostException.class,
                () -> map.deleteIfToken(PairLockRegistry.newToken(), HASH_1, HASH_2, rowToken));
        String lease = lock(OTHER_SAE);
        assertThrows(PairLockLostException.class,
                () -> map.deleteIfToken(PEER_SAE, lease, HASH_1, HASH_2, rowToken));
        assertEquals(1, SaeFixtures.countRecords(SQLITE.origin()));
        assertEquals(DeleteOutcome.DELETED, map.deleteIfToken(OTHER_SAE, lease, HASH_1, HASH_2, rowToken));
    }

    @Test
    void getRefusesRowsOlderThanRetention() throws Exception {
        SaeFixtures.insertRow(SQLITE.origin(), HASH_1, HASH_2, PEER_SAE, PEER_SAE, PairLockRegistry.newToken(),
                Instant.now().minus(15, ChronoUnit.DAYS));
        assertTrue(map.get(HASH_1, HASH_2).isEmpty());
    }

    @Test
    void metadataNeedsAToken() {
        assertThrows(IllegalArgumentException.class, () -> new RecordMetadata(Instant.now(),
                RecordAvailability.KEYS_AVAILABLE, PEER_SAE, ORIGIN_SAE, " ", 1));
        assertThrows(IllegalArgumentException.class, () -> new RecordMetadata(Instant.now(),
                RecordAvailability.KEYS_AVAILABLE, PEER_SAE, ORIGIN_SAE, null, 1));
        assertThrows(IllegalArgumentException.class, () -> new RecordMetadata(Instant.now(),
                RecordAvailability.KEYS_AVAILABLE, PEER_SAE, ORIGIN_SAE, "t", 70_000));
    }

    @Test
    void databaseFailuresAreWrappedAsIllegalState() throws Exception {
        DataSource broken = mock(DataSource.class);
        SQLException cause = new SQLException("db down");
        when(broken.getConnection()).thenThrow(cause);
        PairLockRegistry brokenRegistry = new PairLockRegistry(broken);
        AtomicRecordStateMap brokenMap = new AtomicRecordStateMap(ORIGIN_SAE, broken,
                new ClientRecordStateRepository(), brokenRegistry, Duration.ofDays(14));
        String token = PairLockRegistry.newToken();
        assertTrue(brokenRegistry.tryAcquire(pair, ORIGIN_SAE, token));

        assertWrapped(cause, "Failed to read record state.", () -> brokenMap.get(HASH_1, HASH_2));
        assertWrapped(cause, "Failed to write origin record.",
                () -> brokenMap.writeOrigin(token, SaeFixtures.header(HASH_1, HASH_2, PEER_SAE)));
        assertWrapped(cause, "Failed to delete record state.",
                () -> brokenMap.deleteIfToken(token, HASH_1, HASH_2, token));
        assertTrue(brokenRegistry.holds(pair, token), "a failed transaction keeps the lease");
    }

    @Test
    void repositoryFailureInsideTheLeaseRollsBack() throws Exception {
        ClientRecordStateRepository failing = mock(ClientRecordStateRepository.class);
        SQLException cause = new SQLException("constraint");
        doThrow(cause).when(failing).upsert(any(), anyString(), anyString(), any());
        AtomicRecordStateMap failingMap = new AtomicRecordStateMap(ORIGIN_SAE, SQLITE.origin(), failing,
                registry, Duration.ofDays(14));
        SaeFixtures.insertRow(SQLITE.origin(), HASH_1, HASH_2, OTHER_SAE, OTHER_SAE, "old");
        try (Connection connection = SQLITE.origin().getConnection()) {
            SaeFixtures.seedKeyMaterial(connection, HASH_1, HASH_2, fel.cvut.harness.JceAesGcm.encrypt("x".getBytes()));
        }
        String token = lock(ORIGIN_SAE);

        assertWrapped(cause, "Failed to write origin record.",
                () -> failingMap.writeOrigin(token, SaeFixtures.header(HASH_1, HASH_2, PEER_SAE)));
        assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.origin()), "the key material delete was rolled back");
        assertEquals("old", SaeFixtures.rowToken(SQLITE.origin(), HASH_1, HASH_2));
    }

    private String lock(String issuer) {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, issuer, token));
        return token;
    }

    private interface Call {
        void run() throws Exception;
    }

    private static void assertWrapped(SQLException cause, String message, Call call) {
        IllegalStateException ex = assertThrows(IllegalStateException.class, call::run);
        assertEquals(message, ex.getMessage());
        assertInstanceOf(SQLException.class, ex.getCause());
        assertEquals(cause, ex.getCause());
    }
}
