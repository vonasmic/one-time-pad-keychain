package fel.cvut.integration.node;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.ProvisionCluster.ScriptedOperator;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.RemoteException;
import java.util.List;
import java.util.function.UnaryOperator;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Re-provision handover across three SAE nodes (real SQLite each, real NodeCommandsService and
 * pair locks over in-process RMI, production ProvisionSession + PeerRecordSync; HSM/QKD/device
 * mocked).
 *
 * <p>Initial state: ORIGIN (sae-1) shares the pair with PEER A (sae-2): origin row (H1,H2)→A,
 * A row (H2,H1)→origin with key material, one token. PEER B (sae-3) then starts a new share
 * that collides with that pair; the operator confirms deletion, the old share is removed on both
 * nodes under both locks by token, and a new share is created.
 */
@Timeout(60)
@Tag("integration")
class ReprovisionHandoverTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private ProvisionCluster cluster;
    private SaeNode origin;
    private SaeNode peerA;
    private SaeNode peerB;

    @BeforeEach
    void setUp() throws Exception {
        cluster = new ProvisionCluster(SQLITE);
        origin = cluster.origin();
        peerA = cluster.peerA();
        peerB = cluster.peerB();
    }

    @AfterEach
    void tearDown() {
        cluster.close();
    }

    @Test
    void peerBContactsOriginDeletesOldShareAndCreatesNewOne() throws Exception {
        establishOriginToPeerA();
        // Device at B (hashes H2,H1) shares with the original origin.
        ProvisionSession.Outcome out = bToOrigin(new ScriptedOperator(true, true));

        assertEquals(newToken(out), origin.row(HASH_1, HASH_2).orElseThrow().token(),
                "old share deleted on the origin; it holds the new peer row");
        assertTrue(peerA.isEmpty(), "old share deleted on peer A");
        assertTrue(ProvisionCluster.deviceAcked(out));
        assertShared(peerB, HASH_2, HASH_1, origin);
        assertEquals(1, origin.keyMaterial());
        assertEquals(0, peerB.keyMaterial());
        assertTrue(peerA.isEmpty());
    }

    @Test
    void peerBContactsPeerADeletesOldShareAndCreatesNewOne() throws Exception {
        establishOriginToPeerA();
        // Device at B (hashes H1,H2) shares with peer A; A stores reversed (H2,H1).
        ProvisionSession.Outcome out = cluster.session(peerB, new ScriptedOperator(true, true))
                .process(SaeFixtures.record(HASH_1, HASH_2, peerA.id(), List.of()), SaeFixtures.uplink());

        assertTrue(origin.isEmpty());
        assertEquals(newToken(out), peerA.row(HASH_2, HASH_1).orElseThrow().token(),
                "old share deleted on peer A; it holds the new peer row");
        assertTrue(ProvisionCluster.deviceAcked(out));
        assertShared(peerB, HASH_1, HASH_2, peerA);
        assertEquals(1, peerA.keyMaterial());
        assertTrue(origin.isEmpty());
    }

    @Test
    void handoverRefusedWhileAnotherOperationHoldsTheTargetPair() throws Exception {
        String old = establishOriginToPeerA();
        assertTrue(origin.registry.tryAcquire(PairKey.of(HASH_1, HASH_2), peerA.id(), PairLockRegistry.newToken()));

        ScriptedOperator operator = new ScriptedOperator(true, true);
        ProvisionSession.Outcome out = bToOrigin(operator);
        assertEquals(ProvisionSession.LOCK_BUSY_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertEquals(1, operator.confirms.size(), "no delete prompt while the pair is busy");
        assertOldShareIntact(old);
        assertTrue(peerB.pairFree(HASH_1, HASH_2), "B released its own lock");
    }

    @Test
    void handoverDeleteRefusedWhileTheOldCounterpartIsBusy() throws Exception {
        String old = establishOriginToPeerA();
        assertTrue(peerA.registry.tryAcquire(PairKey.of(HASH_1, HASH_2), origin.id(), PairLockRegistry.newToken()));

        ProvisionSession.Outcome out = bToOrigin(new ScriptedOperator(true, true));
        assertEquals(ProvisionSession.LOCK_BUSY_MESSAGE,
                assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out).operatorMessage());
        assertOldShareIntact(old);
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peerB.pairFree(HASH_1, HASH_2));
    }

    @Test
    void handoverRemovesAnOrphanTargetRow() throws Exception {
        establishOriginToPeerA();
        SaeFixtures.age(SQLITE.peer(), HASH_2, HASH_1, java.time.Instant.EPOCH); // A's half expired
        ProvisionSession.Outcome out = bToOrigin(new ScriptedOperator(true, true));
        assertEquals(newToken(out), origin.row(HASH_1, HASH_2).orElseThrow().token());
        assertTrue(ProvisionCluster.deviceAcked(out));
        assertShared(origin, HASH_1, HASH_2, peerB);
    }

    @Test
    void declinedDeleteKeepsOldShareAndLeavesBEmpty() throws Exception {
        String old = establishOriginToPeerA();
        ScriptedOperator operator = new ScriptedOperator(true, false);
        ProvisionSession.Outcome out = bToOrigin(operator);

        assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out);
        assertEquals(2, operator.confirms.size());
        assertTrue(operator.confirms.get(1).contains("permanently delete"));
        assertTrue(peerB.isEmpty());
        assertOldShareIntact(old);
    }

    /** Operator delete vs a replug of the old share while B's operator is deciding. */
    @Test
    void oldShareReprovisionedDuringTheDeletePromptSurvives() throws Exception {
        String old = establishOriginToPeerA();
        String[] newer = new String[1];
        ScriptedOperator operator = new ScriptedOperator(true, true, true, false).during(1, () -> {
            try {
                newer[0] = establishOriginToPeerA();
            } catch (Exception ex) {
                throw new AssertionError(ex);
            }
        });
        ProvisionSession.Outcome out = bToOrigin(operator);

        assertNotEquals(old, newer[0]);
        assertTrue(operator.notifies.contains(ProvisionSession.SHARE_CHANGED_MESSAGE));
        assertEquals(4, operator.confirms.size(), "asked again about the newer share");
        assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out);
        assertOldShareIntact(newer[0]);
        assertTrue(peerB.isEmpty());
    }

    /** Peer A down: the delete takes both locks first, so nothing is deleted. */
    @Test
    void unreachablePeerADuringTheDeleteDeletesNothing() throws Exception {
        String old = establishOriginToPeerA();
        cluster.setUnreachable(peerA.id(), true);

        assertThrows(RemoteException.class, () -> bToOrigin(new ScriptedOperator(true, true)));
        assertTrue(peerB.isEmpty());
        assertOldShareIntact(old);
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peerB.pairFree(HASH_1, HASH_2));

        cluster.setUnreachable(peerA.id(), false);
        ProvisionSession.Outcome out = bToOrigin(new ScriptedOperator(true, true));
        assertTrue(ProvisionCluster.deviceAcked(out));
        assertTrue(peerA.isEmpty());
        assertShared(origin, HASH_1, HASH_2, peerB);
        assertShared(peerB, HASH_2, HASH_1, origin);
    }

    /** Peer A answers the lock but fails on the delete: the remote-first delete keeps the origin row. */
    @Test
    void failedRemoteDeleteKeepsTheShownRow() throws Exception {
        String old = establishOriginToPeerA();
        UnaryOperator<ProvisionSession.RemoteRecords> failingDeleteOnA = real -> new ProvisionSession.RemoteRecords() {
            @Override
            public AtomicRecordStateMap.RecordMetadata get(String saeId, String h1, String h2)
                    throws RemoteException, java.rmi.NotBoundException {
                return real.get(saeId, h1, h2);
            }

            @Override
            public AtomicRecordStateMap.DeleteOutcome delete(
                    String saeId, String h1, String h2, String leaseToken, String rowToken)
                    throws RemoteException, java.rmi.NotBoundException, fel.cvut.node.pairlock.PairLockLostException {
                if (saeId.equals(peerA.id())) {
                    throw new RemoteException("peer A dropped the call");
                }
                return real.delete(saeId, h1, h2, leaseToken, rowToken);
            }
        };
        assertThrows(RemoteException.class, () -> cluster.session(peerB, new ScriptedOperator(true, true), failingDeleteOnA)
                .process(SaeFixtures.record(HASH_2, HASH_1, origin.id(), List.of()), SaeFixtures.uplink()));
        assertOldShareIntact(old);
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peerA.pairFree(HASH_1, HASH_2) && peerB.pairFree(HASH_1, HASH_2));
    }

    @Test
    void unreachableOriginLeavesOldShareIntact() throws Exception {
        String old = establishOriginToPeerA();
        cluster.setUnreachable(origin.id(), true);
        assertThrows(RemoteException.class, () -> bToOrigin(new ScriptedOperator(true)));
        assertTrue(peerB.isEmpty());
        assertOldShareIntact(old);
    }

    private ProvisionSession.Outcome bToOrigin(ScriptedOperator operator) throws Exception {
        return cluster.session(peerB, operator)
                .process(SaeFixtures.record(HASH_2, HASH_1, origin.id(), List.of()), SaeFixtures.uplink());
    }

    /** Origin to peer A through the production session (deleting an earlier share of its own). */
    private String establishOriginToPeerA() throws Exception {
        ProvisionSession.Outcome out = cluster.session(origin, new ScriptedOperator(true, true))
                .process(SaeFixtures.record(HASH_1, HASH_2, peerA.id(), List.of()), SaeFixtures.uplink());
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertTrue(ProvisionCluster.deviceAcked(out));
        String token = origin.row(HASH_1, HASH_2).orElseThrow().token();
        assertOldShareIntact(token);
        return token;
    }

    private void assertOldShareIntact(String token) throws Exception {
        assertEquals(token, origin.row(HASH_1, HASH_2).orElseThrow().token());
        assertEquals(peerA.id(), origin.row(HASH_1, HASH_2).orElseThrow().saeId());
        assertEquals(token, peerA.row(HASH_2, HASH_1).orElseThrow().token());
        assertEquals(1, peerA.keyMaterial());
    }

    private static void assertShared(SaeNode node, String h1, String h2, SaeNode counterpart) {
        var meta = node.map.get(h1, h2).orElseThrow(() -> new AssertionError(node.id() + " has no row"));
        assertEquals(AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE, meta.recordAvailability());
        assertEquals(counterpart.id(), meta.saeId());
        var other = counterpart.map.get(h2, h1).orElseThrow(() -> new AssertionError(counterpart.id() + " has no row"));
        assertEquals(meta.token(), other.token());
    }

    private static String newToken(ProvisionSession.Outcome out) {
        return assertInstanceOf(ProvisionSession.Outcome.Generated.class, out).delivery().operation().token();
    }
}
