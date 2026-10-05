package fel.cvut.db;

import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import org.junit.jupiter.api.BeforeEach;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(60)
class ConcurrentRecordStateTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap stateMap;

    @BeforeEach
    void setUp() {
        stateMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
    }

    @Test
    void concurrentInsertsOfSameHashPairLeaveExactlyOneRow() throws Exception {
        ClientRecord.ClientHeader header = SaeFixtures.header(HASH_1, HASH_2, PEER_SAE);
        int threads = 8;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        AtomicInteger inserted = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                futures.add(executor.submit(() -> {
                    barrier.await(10, TimeUnit.SECONDS);
                    AtomicRecordStateMap.SynchronizeOutcome outcome =
                            stateMap.synchronize(header, ORIGIN_SAE);
                    if (outcome == AtomicRecordStateMap.SynchronizeOutcome.INSERTED) {
                        inserted.incrementAndGet();
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

        assertTrue(inserted.get() >= 1);
        assertEquals(1, SaeFixtures.countRecords(SQLITE.origin()));
        assertTrue(stateMap.get(HASH_1, HASH_2).isPresent());
    }

    @Test
    void concurrentInsertsOfDifferentHashPairsAllSucceed() throws Exception {
        int threads = 8;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AtomicRecordStateMap.SynchronizeOutcome>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                String hash1 = HASH_1.substring(0, 62) + String.format("%02x", i);
                ClientRecord.ClientHeader header = SaeFixtures.header(hash1, HASH_2, PEER_SAE);
                futures.add(executor.submit(() -> {
                    start.await(10, TimeUnit.SECONDS);
                    return stateMap.synchronize(header, ORIGIN_SAE);
                }));
            }
            start.countDown();
            for (Future<AtomicRecordStateMap.SynchronizeOutcome> future : futures) {
                assertEquals(
                        AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                        future.get(15, TimeUnit.SECONDS)
                );
            }
        } finally {
            executor.shutdownNow();
        }
        assertEquals(threads, SaeFixtures.countRecords(SQLITE.origin()));
    }
}
