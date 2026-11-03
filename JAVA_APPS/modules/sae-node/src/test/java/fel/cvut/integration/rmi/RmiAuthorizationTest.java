package fel.cvut.integration.rmi;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.ProvisionCluster.ScriptedOperator;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.pairlock.PairOperation;
import fel.cvut.node.recordManager.AtomicRecordStateMap.DeleteOutcome;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.AccessException;
import java.rmi.RemoteException;
import java.util.List;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Caller identity on RMI comes from the pinned mTLS peer (here: the per-caller in-process stub),
 * never from arguments. Leases are bound to their issuer: knowing a token (row tokens are
 * readable by every SAE) does not let another SAE renew, release, write or delete with it.
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
    void anotherSaeCannotUseTheIssuersLeaseToken() throws Exception {
        share();
        NodeCommands peerAsSeenByOther = cluster.net.stub(other.id(), peerA.id());
        try (PairOperation held = origin.locks.acquire(origin.id(), peerA.id(), HASH_1, HASH_2)) {
            String rowToken = peerAsSeenByOther.getRecordMetadata(HASH_2, HASH_1).token();
            for (String token : List.of(held.token(), rowToken)) {
                assertFalse(peerAsSeenByOther.lockPair(HASH_2, HASH_1, token));
                assertFalse(peerAsSeenByOther.renewPair(HASH_2, HASH_1, token));
                assertFalse(peerAsSeenByOther.releasePair(HASH_2, HASH_1, token));
                assertThrows(PairLockLostException.class,
                        () -> peerAsSeenByOther.deleteRecord(HASH_2, HASH_1, token, rowToken));
            }
            assertTrue(peerA.registry.holds(PairKey.of(HASH_1, HASH_2), held.token()), "the lease survives");
            held.checkpoint();
        }
        assertEquals(1, peerA.records());
        assertEquals(1, peerA.keyMaterial());
    }

    @Test
    void spoofedIssuingSaeIsRejected() throws Exception {
        String fresh = HASH_1.substring(0, 62) + "aa";
        NodeCommands peerAsSeenByOther = cluster.net.stub(other.id(), peerA.id());
        String token = PairLockRegistry.newToken();
        assertTrue(peerAsSeenByOther.lockPair(HASH_2, fresh, token));
        assertEquals(other.id(), peerA.registry.lease(PairKey.of(HASH_2, fresh)).orElseThrow().issuerSaeId(),
                "the lease is in the caller's name");
        assertAccessDenied(() -> peerAsSeenByOther.insert(
                SaeFixtures.record(HASH_2, fresh, origin.id(), List.of("key-1")), token));
        assertTrue(peerA.isEmpty(), "no row may be created under a spoofed issuer");
    }

    @Test
    void partyDeletesOnlyUnderItsOwnLeaseAndOnlyTheShownToken() throws Exception {
        String rowToken = share();
        NodeCommands peerAsSeenByOrigin = cluster.net.stub(origin.id(), peerA.id());
        assertThrows(PairLockLostException.class,
                () -> peerAsSeenByOrigin.deleteRecord(HASH_2, HASH_1, PairLockRegistry.newToken(), rowToken));
        try (PairOperation op = origin.locks.acquire(origin.id(), peerA.id(), HASH_1, HASH_2)) {
            assertEquals(DeleteOutcome.TOKEN_MISMATCH,
                    peerAsSeenByOrigin.deleteRecord(HASH_2, HASH_1, op.token(), PairLockRegistry.newToken()));
            assertEquals(DeleteOutcome.DELETED, peerAsSeenByOrigin.deleteRecord(HASH_2, HASH_1, op.token(), rowToken));
        }
        assertTrue(peerA.isEmpty());
    }

    /** Handover by a non-party: under its own leases on both SAEs and with the shown token. */
    @Test
    void handoverOfACompletedShareByANonPartyUnderItsOwnLeases() throws Exception {
        String rowToken = share();
        try (PairOperation op = other.locks.acquire(origin.id(), peerA.id(), HASH_1, HASH_2)) {
            assertEquals(DeleteOutcome.DELETED,
                    cluster.net.stub(other.id(), peerA.id()).deleteRecord(HASH_2, HASH_1, op.token(), rowToken));
            assertEquals(DeleteOutcome.DELETED,
                    cluster.net.stub(other.id(), origin.id()).deleteRecord(HASH_1, HASH_2, op.token(), rowToken));
        }
        assertTrue(origin.isEmpty());
        assertTrue(peerA.isEmpty());
    }

    private String share() throws Exception {
        assertTrue(ProvisionCluster.deviceAcked(cluster.session(origin, new ScriptedOperator(true))
                .process(SaeFixtures.record(HASH_1, HASH_2, peerA.id(), List.of()), SaeFixtures.uplink())));
        return origin.row(HASH_1, HASH_2).orElseThrow().token();
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
