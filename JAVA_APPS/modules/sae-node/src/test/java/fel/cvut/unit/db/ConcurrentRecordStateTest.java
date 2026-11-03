package fel.cvut.unit.db;

import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** Concurrent operations on one SAE: the pair lock admits one issuer; disjoint pairs do not contend. */
@Timeout(60)
@Tag("unit")
class ConcurrentRecordStateTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap stateMap;
    private PairLockRegistry registry;

    @BeforeEach
    void setUp() {
        stateMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        registry = stateMap.registry();
    }

    @Test
    void concurrentIssuersOfOnePairGetOneLeaseAndOneRow() throws Exception {
        int threads = 8;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        AtomicInteger acquired = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                String issuer = "sae-" + (10 + i);
                futures.add(executor.submit(() -> {
                    String token = PairLockRegistry.newToken();
                    barrier.await(10, TimeUnit.SECONDS);
                    if (registry.tryAcquire(PairKey.of(HASH_1, HASH_2), issuer, token)) {
                        acquired.incrementAndGet();
                        stateMap.writeOrigin(token, SaeFixtures.header(HASH_1, HASH_2, PEER_SAE));
                    }
                    return null;
                }));
            }
            for (Future<?> future : futures) {
                future.get(15, TimeUnit.SECONDS);
            }
        } finally {
            executor.shutdownNow();
        }

        assertEquals(1, acquired.get());
        assertEquals(1, SaeFixtures.countRecords(SQLITE.origin()));
        String holder = registry.lease(PairKey.of(HASH_1, HASH_2)).orElseThrow().token();
        assertEquals(holder, stateMap.get(HASH_1, HASH_2).orElseThrow().token());
    }

    @Test
    void concurrentOperationsOnDifferentPairsAllSucceed() throws Exception {
        int threads = 8;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                String hash1 = HASH_1.substring(0, 62) + String.format("%02x", i);
                futures.add(executor.submit(() -> {
                    start.await(10, TimeUnit.SECONDS);
                    String token = PairLockRegistry.newToken();
                    boolean locked = registry.tryAcquire(PairKey.of(hash1, HASH_2), ORIGIN_SAE, token);
                    stateMap.writeOrigin(token, SaeFixtures.header(hash1, HASH_2, PEER_SAE));
                    registry.release(PairKey.of(hash1, HASH_2), token);
                    return locked;
                }));
            }
            start.countDown();
            for (Future<Boolean> future : futures) {
                assertEquals(true, future.get(15, TimeUnit.SECONDS));
            }
        } finally {
            executor.shutdownNow();
        }
        assertEquals(threads, SaeFixtures.countRecords(SQLITE.origin()));
    }
}
