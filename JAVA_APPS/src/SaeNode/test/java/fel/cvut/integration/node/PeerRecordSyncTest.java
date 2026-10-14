package fel.cvut.integration.node;

import fel.cvut.harness.PeerRecordSyncHarness;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.RemoteException;

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

/**
 * PeerRecordSync against a real peer {@link fel.cvut.node.interNodeCommunication.NodeCommandsService}
 * and two SQLite maps.
 */
@Timeout(60)
@Tag("integration")
class PeerRecordSyncTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private PeerRecordSyncHarness h;

    @BeforeEach
    void setUp() throws Exception {
        h = PeerRecordSyncHarness.open(SQLITE);
    }

    @Test
    void successfulExchangeFinalizesBothSides() throws Exception {
        h.reserveOrigin();
        assertTrue(h.sync()
                .completeNewExchange(PeerRecordSyncHarness.originRecord(), SaeFixtures.uplink())
                .keys()
                .isPresent());
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                h.originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                h.peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability()
        );
        assertEquals(SaeFixtures.padPlain(), h.originMap.get(HASH_1, HASH_2).orElseThrow().padPlainLen());
        assertEquals(SaeFixtures.padPlain(), h.peerMap.get(HASH_2, HASH_1).orElseThrow().padPlainLen());
    }

    @Test
    void lostReplyAfterPeerSuccessRemovesPeerRecord() throws Exception {
        NodeCommands lostReply = mock(NodeCommands.class);
        when(lostReply.synchronize(any(), anyString())).thenAnswer(invocation ->
                h.peer.synchronize(invocation.getArgument(0), invocation.getArgument(1)));
        when(lostReply.lockFetch(anyString(), anyString(), anyString())).thenAnswer(invocation ->
                h.peer.lockFetch(
                        invocation.getArgument(0),
                        invocation.getArgument(1),
                        invocation.getArgument(2)));
        when(lostReply.insert(any(), anyString())).thenAnswer(invocation -> {
            boolean inserted = h.peer.insert(invocation.getArgument(0), invocation.getArgument(1));
            throw new RemoteException("lost reply after insert=" + inserted);
        });
        when(lostReply.removeRecord(anyString(), anyString())).thenAnswer(invocation ->
                h.peer.removeRecord(invocation.getArgument(0), invocation.getArgument(1)));
        when(h.rmi.connectBySaeId(PEER_SAE)).thenReturn(lostReply);
        h.reserveOrigin();
        assertThrows(RemoteException.class, () ->
                h.sync().completeNewExchange(PeerRecordSyncHarness.originRecord(), SaeFixtures.uplink()));
        h.assertBothEmptyAndReinsertable();
    }

    @Test
    void originFinalizeFailureRemovesPeerRecord() throws Exception {
        AtomicRecordStateMap spyOrigin = spy(h.originMap);
        doReturn(false).when(spyOrigin).finishRecordInsert(anyString(), anyString());
        spyOrigin.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE);
        assertThrows(IllegalStateException.class, () ->
                h.sync(spyOrigin).completeNewExchange(PeerRecordSyncHarness.originRecord(), SaeFixtures.uplink()));
        assertTrue(spyOrigin.get(HASH_1, HASH_2).isEmpty());
        assertTrue(h.peerMap.get(HASH_2, HASH_1).isEmpty());
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                h.originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        h.originMap.tryDelete(HASH_1, HASH_2, ORIGIN_SAE);
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                h.peerMap.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), PEER_SAE)
        );
    }
}
