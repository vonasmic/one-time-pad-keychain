package fel.cvut.integration.rmi;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.ProvisionCluster.ScriptedOperator;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordAvailability;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.AccessException;
import java.rmi.RemoteException;
import java.util.List;
import java.util.Optional;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F-01 over in-process RMI with three real nodes: the authenticated caller (not call arguments)
 * decides. ORIGIN (sae-1) and PEER A (sae-2) share the pair; OTHER (sae-3) is not a party.
 */
@Timeout(60)
@Tag("integration")
class RmiAuthorizationTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private ProvisionCluster cluster;
    private SaeNode origin;
    private SaeNode peerA;
    private SaeNode other;

    @BeforeEach
    void setUp() throws Exception {
        cluster = new ProvisionCluster(SQLITE);
        origin = cluster.origin();
        peerA = cluster.peerA();
        other = cluster.peerB();
    }

    @AfterEach
    void tearDown() {
        cluster.close();
    }

    @Test
    void nonPartyCannotRemoveOrMarkAForeignShare() throws Exception {
        share(false);
        NodeCommands originAsSeenByOther = cluster.net.stub(other.id(), origin.id());
        NodeCommands peerAsSeenByOther = cluster.net.stub(other.id(), peerA.id());

        assertAccessDenied(() -> originAsSeenByOther.removeRecord(HASH_1, HASH_2));
        assertAccessDenied(() -> peerAsSeenByOther.removeRecord(HASH_2, HASH_1));
        assertAccessDenied(() -> peerAsSeenByOther.markOriginProvisioned(HASH_2, HASH_1));

        assertEquals(Optional.of(RecordAvailability.RECORD_SHARED), origin.state(HASH_1, HASH_2));
        assertEquals(Optional.of(RecordAvailability.RECORD_SHARED), peerA.state(HASH_2, HASH_1));
        assertEquals(1, peerA.keyMaterial());
    }

    @Test
    void partyMayMarkAndRemove() throws Exception {
        share(false);
        NodeCommands peerAsSeenByOrigin = cluster.net.stub(origin.id(), peerA.id());
        assertTrue(peerAsSeenByOrigin.markOriginProvisioned(HASH_2, HASH_1));
        assertEquals(Optional.of(RecordAvailability.ORIGIN_PROVISIONED), peerA.state(HASH_2, HASH_1));
        peerAsSeenByOrigin.removeRecord(HASH_2, HASH_1);
        assertEquals(Optional.empty(), peerA.state(HASH_2, HASH_1));
    }

    @Test
    void spoofedIssuingSaeIsRejected() throws Exception {
        String fresh = HASH_1.substring(0, 62) + "aa";
        NodeCommands peerAsSeenByOther = cluster.net.stub(other.id(), peerA.id());
        assertAccessDenied(() -> peerAsSeenByOther.synchronize(
                SaeFixtures.header(HASH_2, fresh, origin.id()), origin.id()));
        assertAccessDenied(() -> peerAsSeenByOther.lockFetch(HASH_2, fresh, origin.id()));
        assertAccessDenied(() -> peerAsSeenByOther.insert(
                SaeFixtures.record(HASH_2, fresh, origin.id(), List.of("key-1")), origin.id()));
        assertTrue(peerA.isEmpty(), "no row may be created under a spoofed issuer");
    }

    @Test
    void nonPartyCannotDeleteAnInProgressShare() throws Exception {
        assertEquals(
                fel.cvut.node.recordManager.AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                origin.map.synchronize(SaeFixtures.header(HASH_1, HASH_2, peerA.id()), origin.id()));
        NodeCommands originAsSeenByOther = cluster.net.stub(other.id(), origin.id());
        assertAccessDenied(() -> originAsSeenByOther.deleteShare(HASH_1, HASH_2));
        assertEquals(Optional.of(RecordAvailability.RECORD_SYNCHRONIZATION), origin.state(HASH_1, HASH_2));
    }

    @Test
    void handoverOfCompletedShareByNonPartyStillWorks() throws Exception {
        share(true);
        cluster.net.stub(other.id(), origin.id()).deleteShare(HASH_1, HASH_2);
        assertTrue(origin.isEmpty());
        assertTrue(peerA.isEmpty(), "remote-first: peer A row removed before the origin row");
    }

    private void share(boolean provisioned) throws Exception {
        ProvisionSession.Outcome out = cluster.session(origin, new ScriptedOperator(true))
                .process(SaeFixtures.record(HASH_1, HASH_2, peerA.id(), List.of()), SaeFixtures.uplink());
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        if (provisioned) {
            cluster.markProvisioned(origin, peerA, HASH_1, HASH_2);
        }
    }

    private static void assertAccessDenied(org.junit.jupiter.api.function.Executable call) {
        RemoteException ex = assertThrows(RemoteException.class, call);
        Throwable cause = ex;
        while (cause != null && !(cause instanceof AccessException)) {
            cause = cause.getCause();
        }
        assertInstanceOf(AccessException.class, cause, "expected AccessException, got " + ex);
    }
}
