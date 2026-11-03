package fel.cvut.unit.node;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.ProvisionCluster.ScriptedOperator;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.List;
import java.util.function.UnaryOperator;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

/**
 * Operator-facing branches of {@link ProvisionSession} on the production wiring (pair locks,
 * PeerRecordSync, RmiRemoteRecords, in-process RMI, SQLite per SAE).
 */
@Timeout(60)
@Tag("unit")
class ProvisionSessionTest {

    private static final List<RmiManager.SaeNode> DIRECTORY = List.of(
            new RmiManager.SaeNode(ORIGIN_SAE, "Prague"),
            new RmiManager.SaeNode(PEER_SAE, "Brno"),
            new RmiManager.SaeNode(OTHER_SAE, "Paris"));
    private static final String KEPT = "Existing keys were kept. No keys were sent to the device.";

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private ProvisionCluster cluster;
    private SaeNode origin;
    private SaeNode peer;
    private SaeNode other;

    @BeforeEach
    void setUp() throws Exception {
        cluster = new ProvisionCluster(SQLITE);
        origin = cluster.origin();
        peer = cluster.peerA();
        other = cluster.peerB();
    }

    @AfterEach
    void tearDown() {
        cluster.close();
    }

    @Test
    void confirmedGenerateHoldsBothLocksUntilTheDeliveryCloses() throws Exception {
        ScriptedOperator operator = new ScriptedOperator(true);
        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, operator);
        ProvisionSession.Outcome.Generated generated = assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertArrayEquals(ProvisionCluster.DOWNLINK, generated.payload());
        assertEquals(1, operator.confirms.size());
        assertTrue(operator.confirms.get(0).contains("Generate new keys now?"));
        assertFalse(origin.pairFree(HASH_1, HASH_2));
        assertFalse(peer.pairFree(HASH_1, HASH_2));
        assertTrue(origin.isEmpty(), "the origin row waits for the device ack");
        assertTrue(peer.row(HASH_2, HASH_1).isPresent(), "the peer row is written before the transfer");

        assertTrue(ProvisionCluster.deviceAcked(out));
        String token = origin.row(HASH_1, HASH_2).orElseThrow().token();
        assertEquals(token, peer.row(HASH_2, HASH_1).orElseThrow().token());
        assertTrue(origin.pairFree(HASH_1, HASH_2));
        assertTrue(peer.pairFree(HASH_1, HASH_2));
    }

    @Test
    void peerInsertFailureHandsNothingToTheDevice() throws Exception {
        when(cluster.qkd.getKeyWithKeyIds(any(), anyList()))
                .thenThrow(new fel.cvut.qkd.Qkd014ClientException("KME down (test)", null));
        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, new ScriptedOperator(true));
        assertEquals(ProvisionSession.PEER_INSERT_FAILED_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertTrue(origin.isEmpty() && peer.isEmpty());
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_1, HASH_2));
    }

    @Test
    void deliveryClosedWithoutDeviceAckDeletesThePeerRow() throws Exception {
        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, new ScriptedOperator(true));
        ProvisionSession.Delivery delivery =
                assertInstanceOf(ProvisionSession.Outcome.Generated.class, out).delivery();
        assertTrue(peer.row(HASH_2, HASH_1).isPresent());
        delivery.close();
        assertTrue(origin.isEmpty() && peer.isEmpty());
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_1, HASH_2));
    }

    @Test
    void declinedGenerateReselectsWithoutLocking() throws Exception {
        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, new ScriptedOperator(false));
        assertInstanceOf(ProvisionSession.Outcome.Reselect.class, out);
        assertTrue(origin.pairFree(HASH_1, HASH_2));
        assertTrue(peer.pairFree(HASH_1, HASH_2));
    }

    @Test
    void pairLockedOnThePeerIsReportedBusyAndReleasesTheFirstLock() throws Exception {
        String foreign = PairLockRegistry.newToken();
        assertTrue(peer.registry.tryAcquire(PairKey.of(HASH_1, HASH_2), OTHER_SAE, foreign));
        ScriptedOperator operator = new ScriptedOperator(true);
        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, operator);
        ProvisionSession.Outcome.InProgress busy = assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out);
        assertEquals("Another operation for this device pair is in progress on an SAE. Retry later.",
                busy.operatorMessage());
        assertEquals(List.of(busy.operatorMessage()), operator.notifies);
        assertTrue(origin.pairFree(HASH_1, HASH_2), "the first lock was released");
        assertTrue(peer.registry.holds(PairKey.of(HASH_1, HASH_2), foreign), "no takeover");
    }

    @Test
    void ownShareAsksBeforeDeleteAndKeepsItWhenDeclined() throws Exception {
        String token = shareOriginToPeer();
        ScriptedOperator operator = new ScriptedOperator(false);
        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, operator);
        assertEquals(KEPT, assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertTrue(operator.confirms.get(0).contains("Shared keys already exist with SAE"));
        assertTrue(operator.confirms.get(0).contains("Brno"));
        assertTrue(operator.confirms.get(0).contains("Delete them and generate new keys?"));
        assertEquals(token, origin.row(HASH_1, HASH_2).orElseThrow().token());
        assertEquals(token, peer.row(HASH_2, HASH_1).orElseThrow().token());
    }

    @Test
    void ownShareDeletedWhenConfirmedThenRegenerated() throws Exception {
        String old = shareOriginToPeer();
        ScriptedOperator operator = new ScriptedOperator(true);
        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, operator);
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertEquals(1, operator.confirms.size(), "no second generate prompt after the delete");
        assertTrue(origin.row(HASH_1, HASH_2).isEmpty());
        assertNotEquals(old, peer.row(HASH_2, HASH_1).orElseThrow().token(), "new peer row");
        assertTrue(ProvisionCluster.deviceAcked(out));
        assertNotEquals(old, origin.row(HASH_1, HASH_2).orElseThrow().token());
    }

    @Test
    void peerDeviceGetsTheStoredHalfAndBothRowsAreConsumedRemoteFirst() throws Exception {
        shareOriginToPeer();
        ScriptedOperator operator = new ScriptedOperator();
        ProvisionSession.Outcome out = process(peer, ORIGIN_SAE, HASH_2, HASH_1, operator);
        ProvisionSession.Outcome.Existing existing = assertInstanceOf(ProvisionSession.Outcome.Existing.class, out);
        assertArrayEquals(ProvisionCluster.DOWNLINK, existing.payload());
        assertTrue(operator.confirms.isEmpty());
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty());
        assertTrue(ProvisionCluster.deviceAcked(out));
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_1, HASH_2));
    }

    @Test
    void shareWithAnotherSaeIsUsedWhenConfirmed() throws Exception {
        shareOtherToOrigin();
        ScriptedOperator operator = new ScriptedOperator(true);
        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, operator);
        assertInstanceOf(ProvisionSession.Outcome.Existing.class, out);
        assertEquals(1, operator.confirms.size());
        assertTrue(operator.confirms.get(0).contains("Paris (sae-3)"));
        assertTrue(origin.isEmpty() && other.isEmpty());
        assertTrue(ProvisionCluster.deviceAcked(out));
    }

    @Test
    void shareWithAnotherSaeKeptWhenDeleteDeclined() throws Exception {
        String token = shareOtherToOrigin();
        ScriptedOperator operator = new ScriptedOperator(false, false);
        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, operator);
        assertEquals(KEPT, assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertEquals(2, operator.confirms.size());
        assertTrue(operator.confirms.get(1).contains("permanently delete those keys"));
        assertTrue(operator.confirms.get(1).contains("Paris (sae-3)"));
        assertEquals(token, origin.row(HASH_1, HASH_2).orElseThrow().token());
        assertEquals(token, other.row(HASH_2, HASH_1).orElseThrow().token());
    }

    @Test
    void shareWithAnotherSaeDeletedOnBothWhenConfirmed() throws Exception {
        shareOtherToOrigin();
        ScriptedOperator operator = new ScriptedOperator(false, true);
        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, operator);
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertEquals(2, operator.confirms.size());
        assertTrue(other.isEmpty(), "the counterpart on the third SAE was deleted");
        assertTrue(ProvisionCluster.deviceAcked(out));
        assertEquals(PEER_SAE, origin.row(HASH_1, HASH_2).orElseThrow().saeId());
    }

    @Test
    void targetSharingThePairWithAnotherSaeIsDeletedOnlyWhenConfirmed() throws Exception {
        // The target (peer) holds a share of the reversed pair with the third SAE.
        String token = SaeFixtures.share(other.map, peer.store, peer.registry, PEER_SAE, HASH_1, HASH_2,
                List.of("k"));
        ScriptedOperator declining = new ScriptedOperator(true, false);
        ProvisionSession.Outcome kept = process(origin, PEER_SAE, HASH_1, HASH_2, declining);
        assertEquals(KEPT, assertInstanceOf(ProvisionSession.Outcome.InProgress.class, kept).operatorMessage());
        assertTrue(declining.confirms.get(1).contains("Paris (sae-3)"));
        assertEquals(token, peer.row(HASH_2, HASH_1).orElseThrow().token());
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_1, HASH_2),
                "locks are not held across the prompt");

        ProvisionSession.Outcome out = process(origin, PEER_SAE, HASH_1, HASH_2, new ScriptedOperator(true, true));
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertTrue(other.isEmpty());
        assertTrue(ProvisionCluster.deviceAcked(out));
        assertEquals(ORIGIN_SAE, peer.row(HASH_2, HASH_1).orElseThrow().saeId());
    }

    @Test
    void ownIssuedShareOnTheOriginDeviceIsNotResent() throws Exception {
        // Origin device of another SAE's share asks this SAE (issuer) with the other target.
        shareOriginToPeer();
        ScriptedOperator operator = new ScriptedOperator(true);
        ProvisionSession.Outcome out = process(origin, OTHER_SAE, HASH_1, HASH_2, operator);
        assertEquals(ProvisionSession.OWN_ISSUED_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertEquals(2, peer.records() + origin.records());
    }

    @Test
    void smallerChipIsRefused() throws Exception {
        shareOriginToPeer();
        ScriptedOperator operator = new ScriptedOperator();
        var small = new fel.cvut.se.SeSessionUplink(
                new byte[fel.cvut.se.SeConstants.CLIENT_HASH_LEN], fel.cvut.se.SeConstants.RMEM_OVERHEAD + 1, 1,
                new byte[fel.cvut.se.SeConstants.FILL_ID_LEN], new byte[fel.cvut.se.SeConstants.MLKEM_PK_LEN],
                List.of(SaeFixtures.peer("peer")));
        ProvisionSession.Outcome out = cluster.session(peer, operator, UnaryOperator.identity(), DIRECTORY)
                .process(SaeFixtures.record(HASH_2, HASH_1, ORIGIN_SAE, List.of()), small);
        String message = assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage();
        assertTrue(message.startsWith("The shared pads are "), message);
        assertEquals(1, peer.records());
    }

    @Test
    void unreachableCounterpartKeepsTheRow() throws Exception {
        shareOriginToPeer();
        cluster.setUnreachable(ORIGIN_SAE, true);
        ProvisionSession.Outcome out = process(peer, ORIGIN_SAE, HASH_2, HASH_1, new ScriptedOperator());
        assertEquals(ProvisionSession.UNREACHABLE_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertEquals(1, peer.records());
        assertTrue(peer.pairFree(HASH_1, HASH_2));
    }

    @Test
    void peerRowWithoutTheOriginRowIsDeletedAsOrphan() throws Exception {
        shareOriginToPeer();
        SaeFixtures.age(SQLITE.origin(), HASH_1, HASH_2, java.time.Instant.EPOCH); // origin row expired
        ProvisionSession.Outcome out = process(peer, ORIGIN_SAE, HASH_2, HASH_1, new ScriptedOperator());
        assertEquals(ProvisionSession.ORPHAN_DELETED_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertTrue(peer.isEmpty());
    }

    @Test
    void mismatchedTokensAreNotDeliveredAndBothRowsAreDeleted() throws Exception {
        shareOriginToPeer();
        SaeFixtures.insertRow(SQLITE.origin(), HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE, PairLockRegistry.newToken());
        ProvisionSession.Outcome out = process(peer, ORIGIN_SAE, HASH_2, HASH_1, new ScriptedOperator());
        assertEquals(ProvisionSession.ORPHAN_DELETED_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertTrue(peer.isEmpty());
        assertTrue(origin.isEmpty(), "the origin row naming this SAE was deleted under both locks");
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_1, HASH_2));
    }

    @Test
    void payloadMissingIsReported() throws Exception {
        String token = PairLockRegistry.newToken();
        SaeFixtures.insertRow(SQLITE.origin(), HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE, token);
        SaeFixtures.insertRow(SQLITE.peer(), HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE, token);
        ProvisionSession.Outcome out = process(peer, ORIGIN_SAE, HASH_2, HASH_1, new ScriptedOperator());
        assertEquals(ProvisionSession.PAYLOAD_MISSING_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertEquals(1, peer.records());
    }

    private ProvisionSession.Outcome process(
            SaeNode local, String target, String h1, String h2, ScriptedOperator operator) throws Exception {
        return cluster.session(local, operator, UnaryOperator.identity(), DIRECTORY)
                .process(SaeFixtures.record(h1, h2, target, List.of()), SaeFixtures.uplink());
    }

    /** Share issued by ORIGIN for the device pair, peer half stored on PEER. */
    private String shareOriginToPeer() throws Exception {
        return SaeFixtures.share(origin.map, peer.store, peer.registry, PEER_SAE, HASH_1, HASH_2, List.of("k"));
    }

    /** Share issued by OTHER for which ORIGIN stores the peer half (origin row on OTHER). */
    private String shareOtherToOrigin() throws Exception {
        return SaeFixtures.share(other.map, origin.store, origin.registry, ORIGIN_SAE, HASH_2, HASH_1, List.of("k"));
    }

    @SuppressWarnings("unused")
    private static AtomicRecordStateMap.RecordAvailability unused() {
        return AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE;
    }
}
