package fel.cvut.rmi;

import fel.cvut.harness.InProcessRmi;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaePostgresExtension;
import fel.cvut.node.Address;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.NodeRef;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.qkd.Qkd014Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;
import java.util.List;
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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@Timeout(90)
class ConcurrentRmiTest {

    @RegisterExtension
    static final SaePostgresExtension POSTGRES = new SaePostgresExtension();

    private Qkd014Client qkd;
    private NodeCommandsService peerService;

    @BeforeEach
    void setUp() {
        qkd = SaeFixtures.mockQkd();
        peerService = SaeFixtures.commands(
                SaeFixtures.peerRef(),
                POSTGRES.peer(),
                qkd,
                JceAesGcm.mockHsm()
        );
    }

    @Test
    void concurrentInsertsOfSameHashPairLeaveOnePeerRow() throws Exception {
        ClientRecord record = SaeFixtures.record(HASH_1, HASH_2, ORIGIN_SAE, List.of("key-1"));
        try (InProcessRmi rmi = InProcessRmi.export(peerService)) {
            NodeCommands stub = rmi.stub();
            int threads = 8;
            ExecutorService executor = Executors.newFixedThreadPool(threads);
            CyclicBarrier barrier = new CyclicBarrier(threads);
            AtomicInteger successes = new AtomicInteger();
            List<Future<?>> futures = new ArrayList<>();
            try {
                for (int i = 0; i < threads; i++) {
                    futures.add(executor.submit(() -> {
                        barrier.await(15, TimeUnit.SECONDS);
                        if (stub.insert(record, ORIGIN_SAE)) {
                            successes.incrementAndGet();
                        }
                        return null;
                    }));
                }
                for (Future<?> future : futures) {
                    future.get(30, TimeUnit.SECONDS);
                }
            } finally {
                executor.shutdownNow();
            }
            assertTrue(successes.get() >= 1);
            assertEquals(1, SaeFixtures.countRecords(POSTGRES.peer()));
            AtomicRecordStateMap peerMap = SaeFixtures.stateMap(PEER_SAE, POSTGRES.peer());
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE,
                    peerMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
            );
        }
    }

    @Test
    void concurrentInsertsOfDifferentHashPairsAllSucceed() throws Exception {
        try (InProcessRmi rmi = InProcessRmi.export(peerService)) {
            NodeCommands stub = rmi.stub();
            int threads = 8;
            ExecutorService executor = Executors.newFixedThreadPool(threads);
            CyclicBarrier barrier = new CyclicBarrier(threads);
            List<Future<Boolean>> futures = new ArrayList<>();
            try {
                for (int i = 0; i < threads; i++) {
                    String hash1 = HASH_1.substring(0, 62) + String.format("%02x", i);
                    ClientRecord record = SaeFixtures.record(hash1, HASH_2, ORIGIN_SAE, List.of("key-1"));
                    futures.add(executor.submit(() -> {
                        barrier.await(15, TimeUnit.SECONDS);
                        return stub.insert(record, ORIGIN_SAE);
                    }));
                }
                for (Future<Boolean> future : futures) {
                    assertTrue(future.get(30, TimeUnit.SECONDS));
                }
            } finally {
                executor.shutdownNow();
            }
            assertEquals(threads, SaeFixtures.countRecords(POSTGRES.peer()));
        }
    }

    @Test
    void mixedRpcsFromSeveralClientsDoNotCorruptState() throws Exception {
        try (InProcessRmi rmi = InProcessRmi.export(peerService)) {
            NodeCommands stub = rmi.stub();
            int threads = 12;
            ExecutorService executor = Executors.newFixedThreadPool(threads);
            CyclicBarrier barrier = new CyclicBarrier(threads);
            List<Future<?>> futures = new ArrayList<>();
            try {
                for (int i = 0; i < threads; i++) {
                    int index = i;
                    futures.add(executor.submit(() -> {
                        barrier.await(15, TimeUnit.SECONDS);
                        String hash1 = HASH_1.substring(0, 62) + String.format("%02x", index);
                        ClientRecord record = SaeFixtures.record(hash1, HASH_2, ORIGIN_SAE, List.of("key-1"));
                        stub.insert(record, ORIGIN_SAE);
                        stub.ping(new Address("127.0.0.1", 1));
                        stub.getRecordMetadata(hash1, HASH_2);
                        stub.removeRecord(hash1, HASH_2);
                        return null;
                    }));
                }
                for (Future<?> future : futures) {
                    assertDoesNotThrow(() -> future.get(30, TimeUnit.SECONDS));
                }
            } finally {
                executor.shutdownNow();
            }
            assertEquals(0, SaeFixtures.countRecords(POSTGRES.peer()));
        }
    }

    @Test
    void twoExportedNodesAcceptConcurrentInsertsOnSeparateDatabases() throws Exception {
        NodeCommandsService originService = SaeFixtures.commands(
                new NodeRef(new Address("127.0.0.1", 2010), ORIGIN_SAE),
                POSTGRES.origin(),
                qkd,
                JceAesGcm.mockHsm()
        );
        try (InProcessRmi originRmi = InProcessRmi.export(originService);
             InProcessRmi peerRmi = InProcessRmi.export(peerService)) {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            CyclicBarrier barrier = new CyclicBarrier(2);
            try {
                Future<Boolean> originInsert = executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    return originRmi.stub().insert(
                            SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of("key-1")),
                            PEER_SAE
                    );
                });
                Future<Boolean> peerInsert = executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    return peerRmi.stub().insert(
                            SaeFixtures.record(HASH_1, HASH_2, ORIGIN_SAE, List.of("key-1")),
                            ORIGIN_SAE
                    );
                });
                assertTrue(originInsert.get(30, TimeUnit.SECONDS));
                assertTrue(peerInsert.get(30, TimeUnit.SECONDS));
            } finally {
                executor.shutdownNow();
            }
            assertEquals(1, SaeFixtures.countRecords(POSTGRES.origin()));
            assertEquals(1, SaeFixtures.countRecords(POSTGRES.peer()));
        }
    }
}
