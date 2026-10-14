package fel.cvut.unit.node;

import fel.cvut.harness.PeerRecordSyncHarness;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.qkd.Qkd014ClientException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.RemoteException;
import java.time.Instant;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * PeerRecordSync rollback with mocked RMI/QKD. Failures assert both empty and reinsertable.
 */
@Timeout(60)
@Tag("unit")
class PeerRecordSyncTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private PeerRecordSyncHarness h;

    @BeforeEach
    void setUp() throws Exception {
        h = PeerRecordSyncHarness.open(SQLITE);
    }

    @Test
    void connectFailureLeavesBothEmptyAndReinsertable() throws Exception {
        when(h.rmi.connectBySaeId(anyString())).thenThrow(new RemoteException("peer down"));
        h.reserveOrigin();
        assertThrows(RemoteException.class, () ->
                h.sync().completeNewExchange(PeerRecordSyncHarness.originRecord(), SaeFixtures.uplink()));
        h.assertBothEmptyAndReinsertable();
    }

    @Test
    void insertFalseLeavesBothEmptyAndReinsertable() throws Exception {
        NodeCommands rejecting = mock(NodeCommands.class);
        when(rejecting.synchronize(any(), anyString()))
                .thenReturn(AtomicRecordStateMap.SynchronizeOutcome.INSERTED);
        when(rejecting.lockFetch(anyString(), anyString(), anyString())).thenReturn(true);
        when(rejecting.insert(any(), anyString())).thenReturn(false);
        when(h.rmi.connectBySaeId(PEER_SAE)).thenReturn(rejecting);
        h.reserveOrigin();
        assertTrue(h.sync()
                .completeNewExchange(PeerRecordSyncHarness.originRecord(), SaeFixtures.uplink())
                .keys()
                .isEmpty());
        h.assertBothEmptyAndReinsertable();
    }

    @Test
    void insertThrowBeforePersistLeavesBothEmptyAndReinsertable() throws Exception {
        NodeCommands dropping = mock(NodeCommands.class);
        when(dropping.synchronize(any(), anyString()))
                .thenReturn(AtomicRecordStateMap.SynchronizeOutcome.INSERTED);
        when(dropping.lockFetch(anyString(), anyString(), anyString())).thenReturn(true);
        when(dropping.insert(any(), anyString())).thenThrow(new RemoteException("drop before persist"));
        when(dropping.removeRecord(anyString(), anyString())).thenReturn(null);
        when(h.rmi.connectBySaeId(PEER_SAE)).thenReturn(dropping);
        h.reserveOrigin();
        assertThrows(RemoteException.class, () ->
                h.sync().completeNewExchange(PeerRecordSyncHarness.originRecord(), SaeFixtures.uplink()));
        h.assertBothEmptyAndReinsertable();
    }

    @Test
    void qkdFailureLeavesBothEmptyAndReinsertable() throws Exception {
        when(h.qkd.getKey(any(), any(), nullable(Integer.class)))
                .thenThrow(new Qkd014ClientException("kme down", 503, null));
        h.reserveOrigin();
        assertThrows(Exception.class, () ->
                h.sync().completeNewExchange(PeerRecordSyncHarness.originRecord(), SaeFixtures.uplink()));
        h.assertBothEmptyAndReinsertable();
    }

    @Test
    void differentSaeShareDoesNotRollbackOrigin() throws Exception {
        AtomicRecordStateMap.RecordMetadata metadata = new AtomicRecordStateMap.RecordMetadata(
                Instant.parse("2026-01-01T00:00:00Z"),
                AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED,
                OTHER_SAE,
                ORIGIN_SAE,
                SaeFixtures.padPlain());
        NodeCommands target = mock(NodeCommands.class);
        when(target.synchronize(any(), anyString()))
                .thenReturn(AtomicRecordStateMap.SynchronizeOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE);
        when(target.getRecordMetadata(anyString(), anyString())).thenReturn(metadata);
        when(h.rmi.connectBySaeId(PEER_SAE)).thenReturn(target);
        h.reserveOrigin();
        ProvisionSession.Exchange.Result result = h.sync()
                .completeNewExchange(PeerRecordSyncHarness.originRecord(), SaeFixtures.uplink());
        assertInstanceOf(ProvisionSession.Exchange.Result.SharedWithDifferentSae.class, result);
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SYNCHRONIZATION,
                h.originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
    }
}
