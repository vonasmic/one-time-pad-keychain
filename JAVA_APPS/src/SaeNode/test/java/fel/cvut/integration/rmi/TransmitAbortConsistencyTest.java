package fel.cvut.integration.rmi;

import fel.cvut.harness.AsCaller;
import fel.cvut.harness.InProcessRmi;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.Address;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.PeerRecordSync;
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

import java.rmi.RemoteException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Tag("integration")
@Timeout(90)
class TransmitAbortConsistencyTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap originMap;
    private AtomicRecordStateMap peerMap;
    private AtomicRecordStateMap otherMap;
    private NodeCommandsService peerService;
    private Qkd014Client qkd;

    @BeforeEach
    void setUp() {
        originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
        otherMap = SaeFixtures.stateMap(OTHER_SAE, SQLITE.other());
        qkd = SaeFixtures.mockQkd();
        peerService = SaeFixtures.commands(SaeFixtures.peerRef(), SQLITE.peer(), qkd, JceAesGcm.mockHsm());
    }

    @Test
    void dropDuringInsertThenSecondSaeRetriesWithoutOrphan() throws Exception {
        DroppingInsert dropping = new DroppingInsert(peerService);
        NodeCommands peerAsOrigin = AsCaller.bind(ORIGIN_SAE, peerService);
        try (InProcessRmi export = InProcessRmi.export(AsCaller.bind(ORIGIN_SAE, dropping))) {
            RmiManager rmi = mock(RmiManager.class);
            when(rmi.connectBySaeId(anyString())).thenAnswer(invocation ->
                    dropping.drop.get() ? peerAsOrigin : export.stub());
            RmiManager otherRmi = mock(RmiManager.class);
            when(otherRmi.connectBySaeId(anyString())).thenReturn(AsCaller.bind(OTHER_SAE, peerService));
            reserve(originMap, ORIGIN_SAE);
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> first = executor.submit(() ->
                        sync(originMap, rmi).completeNewExchange(originRecord(ORIGIN_SAE), SaeFixtures.uplink()));
                assertTrue(dropping.entered.await(15, TimeUnit.SECONDS));
                export.unexport();
                dropping.drop.set(true);
                assertThrows(Exception.class, () -> unwrap(first));
            } finally {
                dropping.drop.set(true);
                executor.shutdownNow();
            }
            assertNoOrphanAvailable();
            reserve(otherMap, OTHER_SAE);
            Optional<List<String>> retry = sync(otherMap, otherRmi)
                    .completeNewExchange(originRecord(OTHER_SAE), SaeFixtures.uplink())
                    .keys();
            assertTrue(retry.isPresent());
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    otherMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
            );
            assertEquals(
                    AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability()
            );
            assertTrue(originMap.get(HASH_1, HASH_2).isEmpty());
            assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
            assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.origin()));
        }
    }

    @Test
    void lostReplyThenImmediateRetryIsReinsertableAndConsistent() throws Exception {
        NodeCommands peerAsOrigin = AsCaller.bind(ORIGIN_SAE, peerService);
        NodeCommands lostReply = mock(NodeCommands.class);
        when(lostReply.synchronize(org.mockito.ArgumentMatchers.any(), anyString())).thenAnswer(invocation ->
                peerAsOrigin.synchronize(invocation.getArgument(0), invocation.getArgument(1)));
        when(lostReply.lockFetch(anyString(), anyString(), anyString())).thenAnswer(invocation ->
                peerAsOrigin.lockFetch(
                        invocation.getArgument(0),
                        invocation.getArgument(1),
                        invocation.getArgument(2)));
        when(lostReply.insert(org.mockito.ArgumentMatchers.any(), anyString())).thenAnswer(invocation -> {
            peerAsOrigin.insert(invocation.getArgument(0), invocation.getArgument(1));
            throw new RemoteException("lost reply");
        });
        when(lostReply.removeRecord(anyString(), anyString())).thenAnswer(invocation ->
                peerAsOrigin.removeRecord(invocation.getArgument(0), invocation.getArgument(1)));
        RmiManager rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(lostReply);
        reserve(originMap, ORIGIN_SAE);
        assertThrows(RemoteException.class, () ->
                sync(originMap, rmi).completeNewExchange(originRecord(ORIGIN_SAE), SaeFixtures.uplink()));
        assertNoOrphanAvailable();
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(AsCaller.bind(OTHER_SAE, peerService));
        reserve(otherMap, OTHER_SAE);
        assertTrue(sync(otherMap, rmi).completeNewExchange(originRecord(OTHER_SAE), SaeFixtures.uplink()).keys().isPresent());
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                otherMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability()
        );
        assertTrue(originMap.get(HASH_1, HASH_2).isEmpty());
    }

    private PeerRecordSync sync(AtomicRecordStateMap origin, RmiManager rmi) {
        return new PeerRecordSync(
                origin == originMap ? SaeFixtures.originRef() : SaeFixtures.otherRef(),
                origin,
                rmi,
                qkd
        );
    }

    private static void reserve(AtomicRecordStateMap map, String issuer) {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                map.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), issuer)
        );
    }

    private static ClientRecord originRecord(String issuer) {
        return SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of());
    }

    private void assertNoOrphanAvailable() throws Exception {
        boolean originAvailable = isAvailable(originMap, HASH_1, HASH_2);
        boolean otherAvailable = isAvailable(otherMap, HASH_1, HASH_2);
        boolean peerAvailable = isAvailable(peerMap, HASH_2, HASH_1);
        if (peerAvailable) {
            assertTrue(originAvailable || otherAvailable);
        }
        if (originAvailable) {
            assertTrue(peerAvailable);
        }
        if (otherAvailable) {
            assertTrue(peerAvailable);
        }
        if (!peerAvailable) {
            assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.peer()));
        }
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.origin()));
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.other()));
    }

    private static boolean isAvailable(AtomicRecordStateMap map, String hash1, String hash2) {
        return map.get(hash1, hash2)
                .filter(metadata -> metadata.recordAvailability()
                        == AtomicRecordStateMap.RecordAvailability.RECORD_SHARED)
                .isPresent();
    }

    private static void unwrap(Future<?> future) throws Exception {
        try {
            future.get(20, TimeUnit.SECONDS);
        } catch (java.util.concurrent.ExecutionException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw ex;
        }
    }

    private static final class DroppingInsert implements NodeCommands {
        private final NodeCommands delegate;
        private final CountDownLatch entered = new CountDownLatch(1);
        private final AtomicBoolean drop = new AtomicBoolean();

        private DroppingInsert(NodeCommands delegate) {
            this.delegate = delegate;
        }

        @Override
        public String ping(Address from) throws RemoteException {
            return delegate.ping(from);
        }

        @Override
        public AtomicRecordStateMap.RecordMetadata getRecordMetadata(String clientHash1, String clientHash2)
                throws RemoteException {
            return delegate.getRecordMetadata(clientHash1, clientHash2);
        }

        @Override
        public AtomicRecordStateMap.SynchronizeOutcome synchronize(
                ClientRecord.ClientHeader clientHeader, String issuingSaeId)
                throws RemoteException {
            return delegate.synchronize(clientHeader, issuingSaeId);
        }

        @Override
        public boolean lockFetch(String clientHash1, String clientHash2, String issuingSaeId)
                throws RemoteException {
            return delegate.lockFetch(clientHash1, clientHash2, issuingSaeId);
        }

        @Override
        public boolean insert(ClientRecord clientRecord, String issuingSaeId) throws RemoteException {
            entered.countDown();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
            while (System.nanoTime() < deadline) {
                if (drop.get()) {
                    throw new RemoteException("connection dropped during insert");
                }
                try {
                    Thread.sleep(10);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new RemoteException("interrupted during insert", ex);
                }
            }
            throw new RemoteException("timed out waiting for drop");
        }

        @Override
        public AtomicRecordStateMap.RecordMetadata removeRecord(String clientHash1, String clientHash2)
                throws RemoteException {
            return delegate.removeRecord(clientHash1, clientHash2);
        }

        @Override
        public boolean markOriginProvisioned(String clientHash1, String clientHash2) throws RemoteException {
            return delegate.markOriginProvisioned(clientHash1, clientHash2);
        }

        @Override
        public void deleteShare(String clientHash1, String clientHash2)
                throws RemoteException, java.rmi.NotBoundException {
            delegate.deleteShare(clientHash1, clientHash2);
        }
    }
}
