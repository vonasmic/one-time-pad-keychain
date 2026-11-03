package fel.cvut.integration.rmi;

import fel.cvut.harness.AsCaller;
import fel.cvut.harness.InProcessRmi;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.Address;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.NodeRef;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.qkd.Qkd014Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.Tag;

import java.rmi.RemoteException;
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
@Tag("integration")
class ConcurrentRmiTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private Qkd014Client qkd;
    private NodeCommandsService peerService;

    @BeforeEach
    void setUp() {
        qkd = SaeFixtures.mockQkd();
        peerService = SaeFixtures.commands(
                SaeFixtures.peerRef(),
                SQLITE.peer(),
                qkd,
                JceAesGcm.mockHsm()
        );
    }

    @Test
    void concurrentInsertsOfSameHashPairLeaveOnePeerRow() throws Exception {
        ClientRecord record = SaeFixtures.record(HASH_1, HASH_2, ORIGIN_SAE, List.of("key-1"));
        try (InProcessRmi rmi = InProcessRmi.export(AsCaller.bind(ORIGIN_SAE, peerService))) {
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
                        // Threads of one issuer run concurrently here, unlike Node.usbLoop: a later
                        // lockPair of the same issuer replaces the lease, and the insert of the
                        // replaced attempt is refused by token.
                        if (lockAndInsert(stub, record) != null) {
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
            assertEquals(1, SaeFixtures.countRecords(SQLITE.peer()));
            AtomicRecordStateMap peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE,
                    peerMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
            );
            assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
        }
    }

    @Test
    void concurrentInsertsOfDifferentHashPairsAllSucceed() throws Exception {
        try (InProcessRmi rmi = InProcessRmi.export(AsCaller.bind(ORIGIN_SAE, peerService))) {
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
                        return lockAndInsert(stub, record) != null;
                    }));
                }
                for (Future<Boolean> future : futures) {
                    assertTrue(future.get(30, TimeUnit.SECONDS));
                }
            } finally {
                executor.shutdownNow();
            }
            assertEquals(threads, SaeFixtures.countRecords(SQLITE.peer()));
        }
    }

    @Test
    void mixedRpcsFromSeveralClientsDoNotCorruptState() throws Exception {
        try (InProcessRmi rmi = InProcessRmi.export(AsCaller.bind(ORIGIN_SAE, peerService))) {
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
                        String token = lockAndInsert(stub, record);
                        stub.ping(new Address("127.0.0.1", 1));
                        assertEquals(token, stub.getRecordMetadata(hash1, HASH_2).token());
                        assertEquals(AtomicRecordStateMap.DeleteOutcome.DELETED,
                                stub.deleteRecord(hash1, HASH_2, token, token));
                        assertTrue(stub.releasePair(hash1, HASH_2, token));
                        return null;
                    }));
                }
                for (Future<?> future : futures) {
                    assertDoesNotThrow(() -> future.get(30, TimeUnit.SECONDS));
                }
            } finally {
                executor.shutdownNow();
            }
            assertEquals(0, SaeFixtures.countRecords(SQLITE.peer()));
        }
    }

    @Test
    void twoExportedNodesAcceptConcurrentInsertsOnSeparateDatabases() throws Exception {
        NodeCommandsService originService = SaeFixtures.commands(
                new NodeRef(new Address("127.0.0.1", 2010), ORIGIN_SAE),
                SQLITE.origin(),
                qkd,
                JceAesGcm.mockHsm()
        );
        try (InProcessRmi originRmi = InProcessRmi.export(AsCaller.bind(PEER_SAE, originService));
             InProcessRmi peerRmi = InProcessRmi.export(AsCaller.bind(ORIGIN_SAE, peerService))) {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            CyclicBarrier barrier = new CyclicBarrier(2);
            try {
                Future<Boolean> originInsert = executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    return lockAndInsert(
                            originRmi.stub(),
                            SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of("key-1"))
                    ) != null;
                });
                Future<Boolean> peerInsert = executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    return lockAndInsert(
                            peerRmi.stub(),
                            SaeFixtures.record(HASH_1, HASH_2, ORIGIN_SAE, List.of("key-1"))
                    ) != null;
                });
                assertTrue(originInsert.get(30, TimeUnit.SECONDS));
                assertTrue(peerInsert.get(30, TimeUnit.SECONDS));
            } finally {
                executor.shutdownNow();
            }
            assertEquals(1, SaeFixtures.countRecords(SQLITE.origin()));
            assertEquals(1, SaeFixtures.countRecords(SQLITE.peer()));
        }
    }

    /** Locks the pair for the caller and inserts under it; the token, or {@code null} when refused. */
    private static String lockAndInsert(NodeCommands stub, ClientRecord record) throws RemoteException {
        ClientRecord.ClientHeader header = record.getClientHeader();
        String token = PairLockRegistry.newToken();
        if (!stub.lockPair(header.clientHash1(), header.clientHash2(), token)) {
            return null;
        }
        try {
            stub.insert(record, token);
            return token;
        } catch (PairLockLostException replaced) {
            return null;
        }
    }
}
