package fel.cvut.unit.db;

import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.db.RecordRetention;
import fel.cvut.db.SharedKeyMaterialRepository;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The peer writes a share row and its key material in one transaction only under the issuer's
 * live pair lease with the matching token.
 */
@Timeout(60)
@Tag("unit")
class SharedKeyMaterialLeaseGuardTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private final AtomicLong clock = new AtomicLong();
    private PairLockRegistry registry;
    private SharedKeyMaterialStore store;
    private final PairKey pair = PairKey.of(HASH_2, HASH_1);

    @BeforeEach
    void setUp() {
        registry = new PairLockRegistry(SQLITE.peer(), Duration.ofMinutes(5), clock::get);
        store = new SharedKeyMaterialStore(SQLITE.peer(), new SharedKeyMaterialRepository(),
                new ClientRecordStateRepository(), JceAesGcm.mockHsm(), new ObjectMapper(), registry,
                Duration.ofDays(RecordRetention.DEFAULT_RETENTION_DAYS));
    }

    @Test
    void writeWithoutLeaseIsRefusedAndWritesNothing() throws Exception {
        assertThrows(PairLockLostException.class,
                () -> store.writeKeysAvailable(record(List.of("k")), ORIGIN_SAE, PairLockRegistry.newToken()));
        assertEmpty();
    }

    @Test
    void writeUnderAnotherIssuersLeaseIsRefused() throws Exception {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, OTHER_SAE, token));
        assertThrows(PairLockLostException.class,
                () -> store.writeKeysAvailable(record(List.of("k")), ORIGIN_SAE, token));
        assertEmpty();
    }

    @Test
    void lateWriteOfAnOldAttemptIsRefusedAndTheNewShareSurvives() throws Exception {
        String oldToken = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, oldToken));
        String newToken = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, newToken), "same issuer replaces its old lease");
        store.writeKeysAvailable(record(List.of("new")), ORIGIN_SAE, newToken);

        assertThrows(PairLockLostException.class,
                () -> store.writeKeysAvailable(record(List.of("old")), ORIGIN_SAE, oldToken));

        assertEquals(newToken, SaeFixtures.rowToken(SQLITE.peer(), HASH_2, HASH_1));
        assertEquals(List.of("new"), store.readPayload(HASH_2, HASH_1).orElseThrow());
    }

    @Test
    void writeAfterTheLeaseExpiredIsRefused() throws Exception {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        clock.addAndGet(Duration.ofMinutes(5).toNanos());
        assertThrows(PairLockLostException.class,
                () -> store.writeKeysAvailable(record(List.of("k")), ORIGIN_SAE, token));
        assertEmpty();
    }

    @Test
    void writeStoresRowAndMaterialWithTheToken() throws Exception {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        store.writeKeysAvailable(record(List.of("a", "b")), ORIGIN_SAE, token);

        assertEquals(token, SaeFixtures.rowToken(SQLITE.peer(), HASH_2, HASH_1));
        assertEquals(List.of("a", "b"), store.readPayload(HASH_2, HASH_1).orElseThrow());
        assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
    }

    private static ClientRecord record(List<String> payload) {
        return SaeFixtures.record(HASH_2, HASH_1, ORIGIN_SAE, payload);
    }

    private static void assertEmpty() throws Exception {
        assertEquals(0, SaeFixtures.countRecords(SQLITE.peer()));
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.peer()));
    }
}
