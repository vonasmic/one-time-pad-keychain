package fel.cvut.integration.rmi;

import fel.cvut.harness.InProcessRmi;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.PeerRecordSync;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.qkd.Qkd014Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Tag("integration")
@Timeout(90)
class MultiSaeCrossfireTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private Qkd014Client qkd;
    private AtomicRecordStateMap originMap;
    private AtomicRecordStateMap peerMap;
    private AtomicRecordStateMap otherMap;
    private NodeCommandsService originService;
    private NodeCommandsService peerService;
    private NodeCommandsService otherService;

    @BeforeEach
    void setUp() {
        qkd = SaeFixtures.mockQkd();
        originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
        otherMap = SaeFixtures.stateMap(OTHER_SAE, SQLITE.other());
        originService = SaeFixtures.commands(SaeFixtures.originRef(), SQLITE.origin(), qkd, JceAesGcm.mockHsm());
        peerService = SaeFixtures.commands(SaeFixtures.peerRef(), SQLITE.peer(), qkd, JceAesGcm.mockHsm());
        otherService = SaeFixtures.commands(SaeFixtures.otherRef(), SQLITE.other(), qkd, JceAesGcm.mockHsm());
    }

    @Test
    void overlappingExchangesLeaveAtMostOneConsistentPair() throws Exception {
        try (InProcessRmi originRmi = InProcessRmi.export(originService);
             InProcessRmi peerRmi = InProcessRmi.export(peerService);
             InProcessRmi otherRmi = InProcessRmi.export(otherService)) {
            RmiManager rmi = rmiManager(originRmi, peerRmi, otherRmi);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            CyclicBarrier barrier = new CyclicBarrier(2);
            try {
                Future<ProvisionSession.Exchange.Result> fromOrigin = executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    reserve(originMap, HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE);
                    return new PeerRecordSync(SaeFixtures.originRef(), originMap, rmi, qkd)
                            .completeNewExchange(SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of()), SaeFixtures.uplink());
                });
                Future<ProvisionSession.Exchange.Result> fromOther = executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    reserve(otherMap, HASH_1, HASH_2, PEER_SAE, OTHER_SAE);
                    return new PeerRecordSync(SaeFixtures.otherRef(), otherMap, rmi, qkd)
                            .completeNewExchange(SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of()), SaeFixtures.uplink());
                });
                exchangeResult(fromOrigin);
                exchangeResult(fromOther);
            } finally {
                executor.shutdownNow();
            }
            assertAtMostOneConsistentPair();
            assertReinsertableAfterCleanup();
        }
    }

    @Test
    void disjointPairsAcrossThreeNodesAllSucceed() throws Exception {
        String pairB1 = HASH_1.substring(0, 62) + "10";
        String pairC1 = HASH_1.substring(0, 62) + "20";
        try (InProcessRmi originRmi = InProcessRmi.export(originService);
             InProcessRmi peerRmi = InProcessRmi.export(peerService);
             InProcessRmi otherRmi = InProcessRmi.export(otherService)) {
            RmiManager rmi = rmiManager(originRmi, peerRmi, otherRmi);
            ExecutorService executor = Executors.newFixedThreadPool(3);
            CyclicBarrier barrier = new CyclicBarrier(3);
            try {
                Future<ProvisionSession.Exchange.Result> a = executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    reserve(originMap, HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE);
                    return new PeerRecordSync(SaeFixtures.originRef(), originMap, rmi, qkd)
                            .completeNewExchange(SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of()), SaeFixtures.uplink());
                });
                Future<ProvisionSession.Exchange.Result> b = executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    reserve(otherMap, pairB1, HASH_2, PEER_SAE, OTHER_SAE);
                    return new PeerRecordSync(SaeFixtures.otherRef(), otherMap, rmi, qkd)
                            .completeNewExchange(SaeFixtures.record(pairB1, HASH_2, PEER_SAE, List.of()), SaeFixtures.uplink());
                });
                Future<ProvisionSession.Exchange.Result> c = executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    reserve(originMap, pairC1, HASH_2, OTHER_SAE, ORIGIN_SAE);
                    return new PeerRecordSync(SaeFixtures.originRef(), originMap, rmi, qkd)
                            .completeNewExchange(SaeFixtures.record(pairC1, HASH_2, OTHER_SAE, List.of()), SaeFixtures.uplink());
                });
                assertTrue(a.get(30, TimeUnit.SECONDS).keys().isPresent());
                assertTrue(b.get(30, TimeUnit.SECONDS).keys().isPresent());
                assertTrue(c.get(30, TimeUnit.SECONDS).keys().isPresent());
            } finally {
                executor.shutdownNow();
            }
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
            );
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability()
            );
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    otherMap.get(pairB1, HASH_2).orElseThrow().recordAvailability()
            );
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    peerMap.get(HASH_2, pairB1).orElseThrow().recordAvailability()
            );
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    originMap.get(pairC1, HASH_2).orElseThrow().recordAvailability()
            );
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    otherMap.get(HASH_2, pairC1).orElseThrow().recordAvailability()
            );
        }
    }

    @Test
    void rapidFireInsertsOnOnePeerLeaveOneRowPerPair() throws Exception {
        try (InProcessRmi peerRmi = InProcessRmi.export(peerService)) {
            NodeCommands stub = peerRmi.stub();
            int threads = 8;
            ExecutorService executor = Executors.newFixedThreadPool(threads);
            CyclicBarrier barrier = new CyclicBarrier(threads);
            AtomicInteger successes = new AtomicInteger();
            List<Future<?>> futures = new ArrayList<>();
            try {
                for (int i = 0; i < threads; i++) {
                    String issuing = i % 2 == 0 ? ORIGIN_SAE : OTHER_SAE;
                    futures.add(executor.submit(() -> {
                        barrier.await(15, TimeUnit.SECONDS);
                        ClientRecord record = SaeFixtures.record(HASH_1, HASH_2, issuing, List.of("key-1"));
                        if (syncLockAndInsert(stub, record, issuing)) {
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
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    peerMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
            );
        }
    }

    private static RmiManager rmiManager(InProcessRmi origin, InProcessRmi peer, InProcessRmi other)
            throws RemoteException, NotBoundException {
        RmiManager rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(anyString())).thenAnswer(invocation -> {
            String id = invocation.getArgument(0);
            if (ORIGIN_SAE.equals(id)) {
                return origin.stub();
            }
            if (PEER_SAE.equals(id)) {
                return peer.stub();
            }
            if (OTHER_SAE.equals(id)) {
                return other.stub();
            }
            throw new RemoteException("unknown SAE " + id);
        });
        return rmi;
    }

    private static void reserve(
            AtomicRecordStateMap map, String hash1, String hash2, String target, String issuer
    ) {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                map.synchronize(SaeFixtures.header(hash1, hash2, target), issuer)
        );
    }

    private void assertAtMostOneConsistentPair() throws Exception {
        boolean originAvailable = isAvailable(originMap, HASH_1, HASH_2);
        boolean otherAvailable = isAvailable(otherMap, HASH_1, HASH_2);
        boolean peerAvailable = isAvailable(peerMap, HASH_2, HASH_1);
        assertTrue(booleanCount(originAvailable, otherAvailable) <= 1);
        if (originAvailable || otherAvailable) {
            assertTrue(peerAvailable);
            assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
        } else {
            assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty());
            assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.peer()));
        }
    }

    private void assertReinsertableAfterCleanup() {
        originMap.forceDelete(HASH_1, HASH_2);
        otherMap.forceDelete(HASH_1, HASH_2);
        peerMap.forceDelete(HASH_2, HASH_1);
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        originMap.tryDelete(HASH_1, HASH_2, ORIGIN_SAE);
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                peerMap.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), PEER_SAE)
        );
        peerMap.tryDelete(HASH_2, HASH_1, PEER_SAE);
    }

    /** The overlapping loser may throw RemoteException; the pair assert runs after both futures. */
    private static Optional<List<String>> exchangeResult(Future<ProvisionSession.Exchange.Result> future)
            throws Exception {
        try {
            return future.get(30, TimeUnit.SECONDS).keys();
        } catch (ExecutionException ex) {
            if (ex.getCause() instanceof RemoteException) {
                return Optional.empty();
            }
            throw ex;
        }
    }

    private static boolean isAvailable(AtomicRecordStateMap map, String hash1, String hash2) {
        return map.get(hash1, hash2)
                .filter(metadata -> metadata.recordAvailability()
                        == AtomicRecordStateMap.RecordAvailability.RECORD_SHARED
                        || metadata.recordAvailability()
                        == AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED)
                .isPresent();
    }

    private static int booleanCount(boolean... values) {
        int count = 0;
        for (boolean value : values) {
            if (value) {
                count++;
            }
        }
        return count;
    }

    private static boolean syncLockAndInsert(NodeCommands stub, ClientRecord record, String issuingSaeId)
            throws RemoteException {
        ClientRecord.ClientHeader header = record.getClientHeader();
        if (stub.synchronize(header, issuingSaeId) != AtomicRecordStateMap.SynchronizeOutcome.INSERTED) {
            return false;
        }
        if (!stub.lockFetch(header.clientHash1(), header.clientHash2(), issuingSaeId)) {
            return false;
        }
        return stub.insert(record, issuingSaeId);
    }
}
