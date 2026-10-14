package fel.cvut.integration.node;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.ProvisionCluster.ScriptedOperator;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.OriginShareCheck;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordAvailability;
import fel.cvut.qkd.Qkd014ClientException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.RemoteException;
import java.util.List;
import java.util.Optional;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

/**
 * Two-node provision lifecycle through the production ProvisionSession FSM, PeerRecordSync,
 * NodeCommandsService over in-process RMI, and real SQLite on both sides.
 */
@Timeout(60)
@Tag("integration")
class ProvisionSessionEndToEndTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private ProvisionCluster cluster;
    private SaeNode origin;
    private SaeNode peer;

    @BeforeEach
    void setUp() throws Exception {
        cluster = new ProvisionCluster(SQLITE);
        origin = cluster.origin();
        peer = cluster.peerA();
    }

    @AfterEach
    void tearDown() {
        cluster.close();
    }

    @Test
    void generateThenDeliverToPeerDeviceClearsBothNodes() throws Exception {
        ProvisionSession.Outcome generated = originSession(new ScriptedOperator(true));
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, generated);
        assertArrayEquals(ProvisionCluster.DOWNLINK, ((ProvisionSession.Outcome.Generated) generated).payload());
        assertEquals(Optional.of(RecordAvailability.RECORD_SHARED), origin.state(HASH_1, HASH_2));
        assertEquals(Optional.of(RecordAvailability.RECORD_SHARED), peer.state(HASH_2, HASH_1));
        assertEquals(0, origin.keyMaterial());
        assertEquals(1, peer.keyMaterial());

        cluster.markProvisioned(origin, peer, HASH_1, HASH_2);

        ScriptedOperator peerOperator = new ScriptedOperator();
        ProvisionSession.Outcome delivered = peerSession(peerOperator);
        assertInstanceOf(ProvisionSession.Outcome.Existing.class, delivered);
        assertTrue(peerOperator.confirms.isEmpty());
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty());
    }

    @Test
    void deliveryRefusedWhileOriginNotProvisioned() throws Exception {
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, originSession(new ScriptedOperator(true)));
        // Peer marked, origin not (lost origin ack).
        assertTrue(peer.map.markOriginProvisioned(HASH_2, HASH_1));

        ProvisionSession.Outcome out = peerSession(new ScriptedOperator());
        assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out);
        assertEquals(OriginShareCheck.IN_PROGRESS_MESSAGE,
                ((ProvisionSession.Outcome.InProgress) out).operatorMessage());
        assertEquals(1, peer.keyMaterial());
        assertEquals(Optional.of(RecordAvailability.RECORD_SHARED), origin.state(HASH_1, HASH_2));
    }

    @Test
    void deliveryWithMissingOriginRowDeletesBoth() throws Exception {
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, originSession(new ScriptedOperator(true)));
        cluster.markProvisioned(origin, peer, HASH_1, HASH_2);
        origin.map.forceDelete(HASH_1, HASH_2);

        ProvisionSession.Outcome out = peerSession(new ScriptedOperator());
        assertEquals(OriginShareCheck.DELETED_MESSAGE,
                ((ProvisionSession.Outcome.InProgress) out).operatorMessage());
        assertTrue(peer.isEmpty());
        assertTrue(origin.isEmpty());
    }

    @Test
    void deliveryWithOriginUnreachableKeepsPeerShare() throws Exception {
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, originSession(new ScriptedOperator(true)));
        cluster.markProvisioned(origin, peer, HASH_1, HASH_2);
        cluster.setUnreachable(origin.id(), true);

        ProvisionSession.Outcome out = peerSession(new ScriptedOperator());
        assertEquals(OriginShareCheck.UNREACHABLE_MESSAGE,
                ((ProvisionSession.Outcome.InProgress) out).operatorMessage());
        assertEquals(1, peer.keyMaterial());
        assertEquals(Optional.of(RecordAvailability.ORIGIN_PROVISIONED), origin.state(HASH_1, HASH_2));
    }

    @Test
    void operatorDeclinesGenerateReselectsAndLeavesNoRows() throws Exception {
        ProvisionSession.Outcome out = originSession(new ScriptedOperator(false));
        assertInstanceOf(ProvisionSession.Outcome.Reselect.class, out);
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty());
    }

    @Test
    void originReprovisionAfterProvisionedDeletesAndRegenerates() throws Exception {
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, originSession(new ScriptedOperator(true)));
        cluster.markProvisioned(origin, peer, HASH_1, HASH_2);

        ScriptedOperator operator = new ScriptedOperator(true);
        ProvisionSession.Outcome out = originSession(operator);
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertTrue(operator.confirms.get(0).contains("Delete them and generate new keys?"));
        assertEquals(Optional.of(RecordAvailability.RECORD_SHARED), origin.state(HASH_1, HASH_2));
        assertEquals(Optional.of(RecordAvailability.RECORD_SHARED), peer.state(HASH_2, HASH_1));
        assertEquals(1, peer.keyMaterial());
    }

    @Test
    void qkdFailureOnPeerInsertRollsBackBothNodes() throws Exception {
        when(cluster.qkd.getKeyWithKeyIds(any(), anyList()))
                .thenThrow(new Qkd014ClientException("KME down (test)", null));
        Exception failure = assertThrows(Exception.class, () -> originSession(new ScriptedOperator(true)));
        assertTrue(
                failure instanceof RemoteException || failure instanceof Qkd014ClientException,
                "unexpected: " + failure);
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty());
        doReturn(SaeFixtures.keyContainer("key-1", Math.max(64, SaeFixtures.padPlain())))
                .when(cluster.qkd).getKeyWithKeyIds(any(), anyList());
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, originSession(new ScriptedOperator(true)));
    }

    @Test
    void peerUnreachableDuringGenerateRollsBackOrigin() throws Exception {
        cluster.setUnreachable(peer.id(), true);
        assertThrows(RemoteException.class, () -> originSession(new ScriptedOperator(true)));
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty());
    }

    private ProvisionSession.Outcome originSession(ScriptedOperator operator) throws Exception {
        return cluster.session(origin, operator)
                .process(SaeFixtures.record(HASH_1, HASH_2, peer.id(), List.of()), SaeFixtures.uplink());
    }

    private ProvisionSession.Outcome peerSession(ScriptedOperator operator) throws Exception {
        return cluster.session(peer, operator)
                .process(SaeFixtures.record(HASH_2, HASH_1, origin.id(), List.of()), SaeFixtures.uplink());
    }
}
