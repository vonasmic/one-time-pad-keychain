package fel.cvut.integration.node;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.ProvisionCluster.ScriptedOperator;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
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

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

/**
 * Two-node provision lifecycle through the production ProvisionSession, pair locks over
 * in-process RMI, PeerRecordSync, NodeCommandsService and real SQLite on both sides.
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
        assertArrayEquals(ProvisionCluster.DOWNLINK,
                assertInstanceOf(ProvisionSession.Outcome.Generated.class, generated).payload());
        assertTrue(ProvisionCluster.deviceAcked(generated));
        var originRow = origin.row(HASH_1, HASH_2).orElseThrow();
        var peerRow = peer.row(HASH_2, HASH_1).orElseThrow();
        assertEquals(RecordAvailability.KEYS_AVAILABLE, originRow.recordAvailability());
        assertEquals(originRow.token(), peerRow.token());
        assertEquals(origin.id(), originRow.issuingSaeId());
        assertEquals(origin.id(), peerRow.issuingSaeId());
        assertEquals(0, origin.keyMaterial());
        assertEquals(1, peer.keyMaterial());

        ScriptedOperator peerOperator = new ScriptedOperator();
        ProvisionSession.Outcome delivered = peerSession(peerOperator);
        assertInstanceOf(ProvisionSession.Outcome.Existing.class, delivered);
        assertTrue(peerOperator.confirms.isEmpty());
        assertTrue(ProvisionCluster.deviceAcked(delivered));
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty());
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_1, HASH_2));
    }

    /**
     * Gap guard: the peer lease was lost while the device was written. No origin row is written;
     * the peer row cannot be deleted without the lease and stays as an orphan for the use-time
     * check.
     */
    @Test
    void gapGuardBeforeShareCompleteRefusesTheCommitWhenALeaseWasLost() throws Exception {
        ProvisionSession.Outcome generated = originSession(new ScriptedOperator(true));
        ProvisionSession.Delivery delivery =
                assertInstanceOf(ProvisionSession.Outcome.Generated.class, generated).delivery();
        assertTrue(peer.registry.release(PairKey.of(HASH_1, HASH_2), delivery.operation().token()));

        assertThrows(PairLockLostException.class, delivery::afterDeviceAck);
        delivery.close();
        assertTrue(delivery.operation().isAborted());
        assertTrue(origin.isEmpty());
        assertTrue(peer.row(HASH_2, HASH_1).isPresent(), "orphan peer row");
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_1, HASH_2));
    }

    /** The peer row is written before the payload is handed out; the origin row only after the ack. */
    @Test
    void peerRowExistsBeforeTheDeviceTransfer() throws Exception {
        ProvisionSession.Outcome generated = originSession(new ScriptedOperator(true));
        String token = assertInstanceOf(ProvisionSession.Outcome.Generated.class, generated)
                .delivery().operation().token();
        assertEquals(token, peer.row(HASH_2, HASH_1).orElseThrow().token());
        assertTrue(origin.isEmpty());
        assertTrue(ProvisionCluster.deviceAcked(generated));
        assertEquals(token, origin.row(HASH_1, HASH_2).orElseThrow().token());
    }

    /** The device never acked (transfer failed): closing the delivery deletes the peer row by token. */
    @Test
    void transferFailureDeletesThePeerRow() throws Exception {
        ProvisionSession.Outcome generated = originSession(new ScriptedOperator(true));
        ProvisionSession.Delivery delivery =
                assertInstanceOf(ProvisionSession.Outcome.Generated.class, generated).delivery();
        assertTrue(peer.row(HASH_2, HASH_1).isPresent());
        delivery.close();
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty(), "the peer row was removed by token");
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_1, HASH_2));
    }

    /** The origin lease was lost during the transfer: no origin row, the peer row is deleted. */
    @Test
    void originLeaseLostBeforeTheOriginWriteDeletesThePeerRow() throws Exception {
        ProvisionSession.Outcome generated = originSession(new ScriptedOperator(true));
        String token = assertInstanceOf(ProvisionSession.Outcome.Generated.class, generated)
                .delivery().operation().token();
        origin.registry.release(PairKey.of(HASH_1, HASH_2), token);

        assertFalse(ProvisionCluster.deviceAcked(generated));
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty(), "the peer row was removed by token");
    }

    /** The peer could not store the share: nothing is handed to the device, nothing is written. */
    @Test
    void qkdFailureOnPeerInsertSendsNothingToTheDeviceAndAllowsARetry() throws Exception {
        when(cluster.qkd.getKeyWithKeyIds(any(), anyList()))
                .thenThrow(new Qkd014ClientException("KME down (test)", null));
        ScriptedOperator operator = new ScriptedOperator(true);
        ProvisionSession.Outcome out = originSession(operator);
        assertEquals(ProvisionSession.PEER_INSERT_FAILED_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertTrue(operator.notifies.contains(ProvisionSession.PEER_INSERT_FAILED_MESSAGE));
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty());
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_1, HASH_2));

        doReturn(SaeFixtures.keyContainer("key-1", Math.max(64, SaeFixtures.padPlain())))
                .when(cluster.qkd).getKeyWithKeyIds(any(), anyList());
        assertTrue(ProvisionCluster.deviceAcked(originSession(new ScriptedOperator(true))));
        assertEquals(1, peer.records());
    }

    @Test
    void peerUnreachableDuringGenerateLeavesNothingLocked() throws Exception {
        cluster.setUnreachable(peer.id(), true);
        assertThrows(RemoteException.class, () -> originSession(new ScriptedOperator(true)));
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty());
        assertTrue(origin.pairFree(HASH_1, HASH_2), "the first lock was released");
    }

    @Test
    void peerRowWhoseOriginRowIsGoneIsDeletedAsOrphan() throws Exception {
        assertTrue(ProvisionCluster.deviceAcked(originSession(new ScriptedOperator(true))));
        SaeFixtures.age(SQLITE.origin(), HASH_1, HASH_2, java.time.Instant.EPOCH);

        ProvisionSession.Outcome out = peerSession(new ScriptedOperator());
        assertEquals(ProvisionSession.ORPHAN_DELETED_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertTrue(peer.isEmpty(), "row and key material are deleted");
    }

    /** Consistency check: tokens differ (crash leftover of another attempt); never delivered. */
    @Test
    void mismatchedTokensAreNeverDeliveredAndBothOrphansAreDeleted() throws Exception {
        assertTrue(ProvisionCluster.deviceAcked(originSession(new ScriptedOperator(true))));
        SaeFixtures.insertRow(SQLITE.origin(), HASH_1, HASH_2, peer.id(), origin.id(), PairLockRegistry.newToken());

        ProvisionSession.Outcome out = peerSession(new ScriptedOperator());
        assertEquals(ProvisionSession.ORPHAN_DELETED_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertTrue(peer.isEmpty());
        assertTrue(origin.isEmpty());
    }

    /** Origin row reclaimed by another SAE's share: the peer row is an orphan, the origin row stays. */
    @Test
    void originRowOfAnotherShareIsNotTouchedWhenThePeerOrphanIsDeleted() throws Exception {
        SaeNode other = cluster.peerB();
        assertTrue(ProvisionCluster.deviceAcked(originSession(new ScriptedOperator(true))));
        String reclaimed = SaeFixtures.share(origin.map, other.store, other.registry, other.id(), HASH_1, HASH_2,
                List.of("k"));

        ProvisionSession.Outcome out = peerSession(new ScriptedOperator());
        assertEquals(ProvisionSession.ORPHAN_DELETED_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertTrue(peer.isEmpty());
        assertEquals(reclaimed, origin.row(HASH_1, HASH_2).orElseThrow().token(), "origin row is not touched");
    }

    @Test
    void deliveryWithOriginUnreachableKeepsPeerShare() throws Exception {
        assertTrue(ProvisionCluster.deviceAcked(originSession(new ScriptedOperator(true))));
        cluster.setUnreachable(origin.id(), true);

        ProvisionSession.Outcome out = peerSession(new ScriptedOperator());
        assertEquals(ProvisionSession.UNREACHABLE_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertEquals(1, peer.keyMaterial());
        assertTrue(origin.row(HASH_1, HASH_2).isPresent());
    }

    @Test
    void originReprovisionDeletesAndRegeneratesWithANewToken() throws Exception {
        assertTrue(ProvisionCluster.deviceAcked(originSession(new ScriptedOperator(true))));
        String old = origin.row(HASH_1, HASH_2).orElseThrow().token();

        ScriptedOperator operator = new ScriptedOperator(true);
        ProvisionSession.Outcome out = originSession(operator);
        assertTrue(operator.confirms.get(0).contains("Delete them and generate new keys?"));
        assertTrue(ProvisionCluster.deviceAcked(out));
        String fresh = origin.row(HASH_1, HASH_2).orElseThrow().token();
        assertNotEquals(old, fresh);
        assertEquals(fresh, peer.row(HASH_2, HASH_1).orElseThrow().token());
        assertEquals(1, peer.keyMaterial());
    }

    /**
     * Operator delete vs a replug that creates a newer share while the operator is deciding:
     * the delete compares the shown token, refuses, re-prompts, and the newer share survives.
     */
    @Test
    void operatorDeleteRacingAReplugKeepsTheNewerShare() throws Exception {
        assertTrue(ProvisionCluster.deviceAcked(originSession(new ScriptedOperator(true))));
        String shown = origin.row(HASH_1, HASH_2).orElseThrow().token();
        String[] newer = new String[1];

        ScriptedOperator operator = new ScriptedOperator(true, false).during(0, () -> {
            try {
                // The device was replugged elsewhere on this SAE and re-provisioned meanwhile.
                assertTrue(ProvisionCluster.deviceAcked(originSession(new ScriptedOperator(true))));
                newer[0] = origin.row(HASH_1, HASH_2).orElseThrow().token();
            } catch (Exception ex) {
                throw new AssertionError(ex);
            }
        });
        ProvisionSession.Outcome out = originSession(operator);

        assertNotEquals(shown, newer[0]);
        assertTrue(operator.notifies.contains(ProvisionSession.SHARE_CHANGED_MESSAGE));
        assertEquals(2, operator.confirms.size(), "the operator is asked again about the newer share");
        assertEquals("Existing keys were kept. No keys were sent to the device.",
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertEquals(newer[0], origin.row(HASH_1, HASH_2).orElseThrow().token());
        assertEquals(newer[0], peer.row(HASH_2, HASH_1).orElseThrow().token());
        assertEquals(1, peer.keyMaterial());
    }

    /**
     * The counterpart already holds a newer row: the remote compare-and-delete keeps it, and the
     * new share overwrites it under both locks.
     */
    @Test
    void operatorDeleteKeepsANewerCounterpartRow() throws Exception {
        assertTrue(ProvisionCluster.deviceAcked(originSession(new ScriptedOperator(true))));
        String newer = PairLockRegistry.newToken();
        SaeFixtures.insertRow(SQLITE.peer(), HASH_2, HASH_1, origin.id(), origin.id(), newer);

        ProvisionSession.Outcome out = originSession(new ScriptedOperator(true));
        String token = assertInstanceOf(ProvisionSession.Outcome.Generated.class, out).delivery().operation().token();
        assertTrue(origin.row(HASH_1, HASH_2).isEmpty(), "the shown origin row was deleted");
        assertEquals(token, peer.row(HASH_2, HASH_1).orElseThrow().token(), "the new share overwrote the newer row");
        assertTrue(ProvisionCluster.deviceAcked(out));
        assertEquals(origin.row(HASH_1, HASH_2).orElseThrow().token(), peer.row(HASH_2, HASH_1).orElseThrow().token());
    }

    @Test
    void operatorDeclinesGenerateReselectsAndLeavesNoRows() throws Exception {
        assertInstanceOf(ProvisionSession.Outcome.Reselect.class, originSession(new ScriptedOperator(false)));
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
