package fel.cvut.node;

import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.RemoteException;
import java.util.List;
import java.util.Optional;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@Timeout(60)
class PeerRecordSyncTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap originMap;
    private AtomicRecordStateMap peerMap;
    private NodeCommandsService peerService;
    private Qkd014Client qkd;
    private RmiManager rmi;

    @BeforeEach
    void setUp() throws Exception {
        originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
        qkd = SaeFixtures.mockQkd();
        peerService = SaeFixtures.commands(
                SaeFixtures.peerRef(),
                SQLITE.peer(),
                qkd,
                JceAesGcm.mockHsm()
        );
        rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(peerService);
    }

    @Test
    void successfulExchangeFinalizesBothSides() throws Exception {
        reserveOrigin();
        Optional<List<String>> material = newSync(originMap).completeNewExchange(originRecord(), SaeFixtures.uplink());
        assertTrue(material.isPresent());
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE,
                peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability()
        );
    }

    @Test
    void connectFailureDeletesOriginAndLeavesPeerEmpty() throws Exception {
        when(rmi.connectBySaeId(anyString())).thenThrow(new RemoteException("peer down"));
        reserveOrigin();
        assertThrows(RemoteException.class, () ->
                newSync(originMap).completeNewExchange(originRecord(), SaeFixtures.uplink()));
        assertBothEmptyAndReinsertable();
    }

    @Test
    void insertFalseDeletesOriginAndDoesNotWipePeer() throws Exception {
        NodeCommands rejecting = mock(NodeCommands.class);
        when(rejecting.synchronize(any(), anyString())).thenReturn(true);
        when(rejecting.lockFetch(anyString(), anyString(), anyString())).thenReturn(true);
        when(rejecting.insert(any(), anyString())).thenReturn(false);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(rejecting);
        reserveOrigin();
        Optional<List<String>> material = newSync(originMap).completeNewExchange(originRecord(), SaeFixtures.uplink());
        assertTrue(material.isEmpty());
        assertBothEmptyAndReinsertable();
    }

    @Test
    void insertThrowBeforePersistCleansBothSides() throws Exception {
        NodeCommands dropping = mock(NodeCommands.class);
        when(dropping.synchronize(any(), anyString())).thenReturn(true);
        when(dropping.lockFetch(anyString(), anyString(), anyString())).thenReturn(true);
        when(dropping.insert(any(), anyString())).thenThrow(new RemoteException("drop before persist"));
        when(dropping.removeRecord(anyString(), anyString())).thenReturn(null);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(dropping);
        reserveOrigin();
        assertThrows(RemoteException.class, () ->
                newSync(originMap).completeNewExchange(originRecord(), SaeFixtures.uplink()));
        assertBothEmptyAndReinsertable();
    }

    @Test
    void lostReplyAfterPeerSuccessRemovesPeerRecord() throws Exception {
        NodeCommands lostReply = mock(NodeCommands.class);
        when(lostReply.synchronize(any(), anyString())).thenAnswer(invocation ->
                peerService.synchronize(invocation.getArgument(0), invocation.getArgument(1)));
        when(lostReply.lockFetch(anyString(), anyString(), anyString())).thenAnswer(invocation ->
                peerService.lockFetch(
                        invocation.getArgument(0),
                        invocation.getArgument(1),
                        invocation.getArgument(2)));
        when(lostReply.insert(any(), anyString())).thenAnswer(invocation -> {
            boolean inserted = peerService.insert(invocation.getArgument(0), invocation.getArgument(1));
            throw new RemoteException("lost reply after insert=" + inserted);
        });
        when(lostReply.removeRecord(anyString(), anyString())).thenAnswer(invocation ->
                peerService.removeRecord(invocation.getArgument(0), invocation.getArgument(1)));
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(lostReply);
        reserveOrigin();
        assertThrows(RemoteException.class, () ->
                newSync(originMap).completeNewExchange(originRecord(), SaeFixtures.uplink()));
        assertBothEmptyAndReinsertable();
    }

    @Test
    void originFinalizeFailureRemovesPeerRecord() throws Exception {
        AtomicRecordStateMap spyOrigin = spy(originMap);
        doReturn(false).when(spyOrigin).finishRecordInsert(anyString(), anyString());
        spyOrigin.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE);
        assertThrows(IllegalStateException.class, () ->
                newSync(spyOrigin).completeNewExchange(originRecord(), SaeFixtures.uplink()));
        assertTrue(spyOrigin.get(HASH_1, HASH_2).isEmpty());
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
    }

    @Test
    void qkdFailureDeletesOriginAndNeverTouchesPeer() throws Exception {
        when(qkd.getKey(any(), any(), nullable(Integer.class)))
                .thenThrow(new Qkd014ClientException("kme down", 503, null));
        reserveOrigin();
        assertThrows(Exception.class, () ->
                newSync(originMap).completeNewExchange(originRecord(), SaeFixtures.uplink()));
        assertBothEmptyAndReinsertable();
    }

    private PeerRecordSync newSync(AtomicRecordStateMap origin) {
        return new PeerRecordSync(SaeFixtures.originRef(), origin, rmi, qkd);
    }

    private static ClientRecord originRecord() {
        return SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of());
    }

    private void reserveOrigin() {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
    }

    private void assertBothEmptyAndReinsertable() {
        assertTrue(originMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(peerMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty());
        assertEquals(0, keyMaterialCountQuiet());
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

    private long keyMaterialCountQuiet() {
        try {
            return SaeFixtures.countKeyMaterial(SQLITE.origin())
                    + SaeFixtures.countKeyMaterial(SQLITE.peer());
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}
