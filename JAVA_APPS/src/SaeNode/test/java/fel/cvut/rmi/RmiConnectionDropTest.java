package fel.cvut.rmi;

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
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.rmi.RemoteException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@Timeout(90)
class RmiConnectionDropTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap originMap;
    private AtomicRecordStateMap peerMap;
    private NodeCommandsService peerService;
    private Qkd014Client qkd;

    @BeforeEach
    void setUp() {
        originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
        qkd = SaeFixtures.mockQkd();
        peerService = SaeFixtures.commands(
                SaeFixtures.peerRef(),
                SQLITE.peer(),
                qkd,
                JceAesGcm.mockHsm()
        );
    }

    @ParameterizedTest
    @EnumSource(DropPoint.class)
    void dropLeavesBothSidesEmptyAndReinsertable(DropPoint dropPoint) throws Exception {
        switch (dropPoint) {
            case CONNECT_FAILS -> connectFails();
            case INSERT_THROWS_BEFORE_PERSIST -> insertThrowsBeforePersist();
            case INSERT_RETURNS_FALSE -> insertReturnsFalse();
            case INSERT_LOST_REPLY -> insertLostReply();
            case ORIGIN_FINISH_FAILS -> originFinishFails();
            case UNEXPORT_BEFORE_INSERT -> unexportBeforeInsert();
            case UNEXPORT_DURING_INSERT -> unexportDuringInsert();
            case REMOVE_RECORD -> dropDuringRemoveRecord();
            case GET_METADATA -> dropDuringGetMetadata();
        }
    }

    private void connectFails() throws Exception {
        RmiManager rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(anyString())).thenThrow(new RemoteException("connect failed"));
        reserveOrigin();
        assertThrows(RemoteException.class, () ->
                sync(originMap, rmi).completeNewExchange(originRecord(), SaeFixtures.uplink()));
        assertBothEmptyAndReinsertable();
    }

    private void insertThrowsBeforePersist() throws Exception {
        try (InProcessRmi ignored = InProcessRmi.export(peerService)) {
            NodeCommands dropping = mock(NodeCommands.class);
            when(dropping.synchronize(any(), anyString())).thenReturn(true);
            when(dropping.lockFetch(anyString(), anyString(), anyString())).thenReturn(true);
            when(dropping.insert(any(), anyString())).thenThrow(new RemoteException("drop before persist"));
            when(dropping.removeRecord(anyString(), anyString())).thenReturn(null);
            RmiManager rmi = mock(RmiManager.class);
            when(rmi.connectBySaeId(PEER_SAE)).thenReturn(dropping);
            reserveOrigin();
            assertThrows(RemoteException.class, () ->
                    sync(originMap, rmi).completeNewExchange(originRecord(), SaeFixtures.uplink()));
            assertBothEmptyAndReinsertable();
        }
    }

    private void insertReturnsFalse() throws Exception {
        NodeCommands rejecting = mock(NodeCommands.class);
        when(rejecting.synchronize(any(), anyString())).thenReturn(true);
        when(rejecting.lockFetch(anyString(), anyString(), anyString())).thenReturn(true);
        when(rejecting.insert(any(), anyString())).thenReturn(false);
        RmiManager rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(rejecting);
        reserveOrigin();
        assertTrue(sync(originMap, rmi).completeNewExchange(originRecord(), SaeFixtures.uplink()).isEmpty());
        assertBothEmptyAndReinsertable();
    }

    private void insertLostReply() throws Exception {
        NodeCommands lostReply = mock(NodeCommands.class);
        when(lostReply.synchronize(any(), anyString())).thenAnswer(invocation ->
                peerService.synchronize(invocation.getArgument(0), invocation.getArgument(1)));
        when(lostReply.lockFetch(anyString(), anyString(), anyString())).thenAnswer(invocation ->
                peerService.lockFetch(
                        invocation.getArgument(0),
                        invocation.getArgument(1),
                        invocation.getArgument(2)));
        when(lostReply.insert(any(), anyString())).thenAnswer(invocation -> {
            peerService.insert(invocation.getArgument(0), invocation.getArgument(1));
            throw new RemoteException("lost reply");
        });
        when(lostReply.removeRecord(anyString(), anyString())).thenAnswer(invocation ->
                peerService.removeRecord(invocation.getArgument(0), invocation.getArgument(1)));
        RmiManager rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(lostReply);
        reserveOrigin();
        assertThrows(RemoteException.class, () ->
                sync(originMap, rmi).completeNewExchange(originRecord(), SaeFixtures.uplink()));
        assertBothEmptyAndReinsertable();
    }

    private void originFinishFails() throws Exception {
        AtomicRecordStateMap spyOrigin = spy(originMap);
        doReturn(false).when(spyOrigin).finishRecordInsert(anyString(), anyString());
        spyOrigin.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE);
        RmiManager rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(peerService);
        assertThrows(IllegalStateException.class, () ->
                sync(spyOrigin, rmi).completeNewExchange(originRecord(), SaeFixtures.uplink()));
        assertTrue(spyOrigin.get(HASH_1, HASH_2).isEmpty());
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty());
        assertBothEmptyAndReinsertable();
    }

    private void unexportBeforeInsert() throws Exception {
        try (InProcessRmi rmiExport = InProcessRmi.export(peerService)) {
            rmiExport.unexport();
            RmiManager rmi = mock(RmiManager.class);
            when(rmi.connectBySaeId(PEER_SAE)).thenReturn(rmiExport.stub());
            reserveOrigin();
            Exception thrown = assertThrows(Exception.class, () ->
                    sync(originMap, rmi).completeNewExchange(originRecord(), SaeFixtures.uplink()));
            assertTrue(thrown instanceof RemoteException || thrown.getCause() instanceof RemoteException);
            assertBothEmptyAndReinsertable();
        }
    }

    private void unexportDuringInsert() throws Exception {
        DroppingInsert dropping = new DroppingInsert(peerService);
        try (InProcessRmi rmiExport = InProcessRmi.export(dropping)) {
            RmiManager rmi = mock(RmiManager.class);
            when(rmi.connectBySaeId(PEER_SAE)).thenAnswer(invocation ->
                    dropping.drop.get() ? peerService : rmiExport.stub());
            reserveOrigin();
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> exchange = executor.submit(() ->
                        sync(originMap, rmi).completeNewExchange(originRecord(), SaeFixtures.uplink()));
                assertTrue(dropping.entered.await(15, TimeUnit.SECONDS));
                rmiExport.unexport();
                dropping.drop.set(true);
                Exception thrown = assertThrows(Exception.class, () -> {
                    try {
                        exchange.get(20, TimeUnit.SECONDS);
                    } catch (java.util.concurrent.ExecutionException ex) {
                        Throwable cause = ex.getCause();
                        if (cause instanceof Exception exception) {
                            throw exception;
                        }
                        throw ex;
                    }
                });
                assertTrue(thrown instanceof RemoteException || thrown.getCause() instanceof RemoteException);
            } finally {
                dropping.drop.set(true);
                executor.shutdownNow();
            }
            assertBothEmptyAndReinsertable();
        }
    }

    private void dropDuringRemoveRecord() throws Exception {
        try (InProcessRmi rmiExport = InProcessRmi.export(peerService)) {
            rmiExport.unexport();
            Exception thrown = assertThrows(Exception.class, () ->
                    rmiExport.stub().removeRecord(HASH_1, HASH_2));
            assertTrue(thrown instanceof RemoteException);
            assertBothEmptyAndReinsertable();
        }
    }

    private void dropDuringGetMetadata() throws Exception {
        try (InProcessRmi rmiExport = InProcessRmi.export(peerService)) {
            rmiExport.unexport();
            Exception thrown = assertThrows(Exception.class, () ->
                    rmiExport.stub().getRecordMetadata(HASH_1, HASH_2));
            assertTrue(thrown instanceof RemoteException);
            assertBothEmptyAndReinsertable();
        }
    }

    private PeerRecordSync sync(AtomicRecordStateMap origin, RmiManager rmi) {
        return new PeerRecordSync(SaeFixtures.originRef(), origin, rmi, qkd);
    }

    private void reserveOrigin() {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
    }

    private static ClientRecord originRecord() {
        return SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of());
    }

    private void assertBothEmptyAndReinsertable() {
        assertTrue(originMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(peerMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty());
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

    enum DropPoint {
        CONNECT_FAILS,
        INSERT_THROWS_BEFORE_PERSIST,
        INSERT_RETURNS_FALSE,
        INSERT_LOST_REPLY,
        ORIGIN_FINISH_FAILS,
        UNEXPORT_BEFORE_INSERT,
        UNEXPORT_DURING_INSERT,
        REMOVE_RECORD,
        GET_METADATA
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
        public byte[] relay(byte[] payload) throws RemoteException {
            return delegate.relay(payload);
        }

        @Override
        public AtomicRecordStateMap.RecordMetadata getRecordMetadata(String clientHash1, String clientHash2)
                throws RemoteException {
            return delegate.getRecordMetadata(clientHash1, clientHash2);
        }

        @Override
        public boolean synchronize(ClientRecord.ClientHeader clientHeader, String issuingSaeId)
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
    }
}
