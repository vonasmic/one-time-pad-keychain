package fel.cvut.integration.rmi;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.PeerRecordSync;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.ShareConsistency;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.pairlock.PairOperation;
import fel.cvut.node.recordManager.ClientRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.rmi.RemoteException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The transfer of the peer row breaks mid-way. Whatever is left behind is never reported as an
 * available share (rule: both rows carry the same token), the pair locks are released, and the
 * next attempt, from the same or another SAE, produces one consistent share.
 */
@Tag("integration")
@Timeout(90)
class TransmitAbortConsistencyTest {

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
    void connectionDroppedAfterThePeerCommittedLeavesAnOrphanThatAnotherSaeReplaces() throws Exception {
        // the peer commits the insert, then the connection dies: the reply and the rollback are lost
        AtomicBoolean dropped = new AtomicBoolean();
        NodeCommands real = origin.rmi.connectBySaeId(peer.id());
        NodeCommands dropping = intercept(real, (name, args) -> {
            if (dropped.get()) {
                throw new RemoteException("connection dropped");
            }
            if (name.equals("insert")) {
                real.insert((ClientRecord) args[0], (String) args[1]);
                dropped.set(true);
                throw new RemoteException("connection dropped during insert");
            }
            return NOT_HANDLED;
        });
        String token;
        try (PairOperation operation = origin.locks.acquire(origin.id(), peer.id(), HASH_1, HASH_2)) {
            token = operation.token();
            assertThrows(RemoteException.class, () -> exchange(origin, syncVia(origin, dropping), token));
        }
        assertTrue(origin.pairFree(HASH_1, HASH_2));
        assertTrue(peer.pairFree(HASH_2, HASH_1), "the lock connection is separate and released the lease");
        assertTrue(origin.row(HASH_1, HASH_2).isEmpty(), "the origin row is written only after the peer row");
        var orphan = peer.row(HASH_2, HASH_1).orElseThrow();
        assertEquals(token, orphan.token());
        assertFalse(ShareConsistency.consistent(orphan, null, peer.id()), "an orphan is never available");

        // another SAE provisions the same client pair with the peer under both locks
        String newer;
        try (PairOperation operation = other.locks.acquire(other.id(), peer.id(), HASH_1, HASH_2)) {
            newer = operation.token();
            exchange(other, other.sync(), newer);
        }
        var otherRow = other.row(HASH_1, HASH_2).orElseThrow();
        var peerRow = peer.row(HASH_2, HASH_1).orElseThrow();
        assertEquals(newer, peerRow.token());
        assertTrue(ShareConsistency.consistent(otherRow, peerRow, other.id()));
        assertEquals(1, peer.keyMaterial(), "the orphan's key material was replaced");
        assertTrue(origin.isEmpty());
    }

    @Test
    void lostInsertReplyRemovesThePeerRowByTokenAndAnImmediateRetrySucceeds() throws Exception {
        NodeCommands real = origin.rmi.connectBySaeId(peer.id());
        NodeCommands lostReply = intercept(real, (name, args) -> {
            if (name.equals("insert")) {
                real.insert((ClientRecord) args[0], (String) args[1]);
                throw new RemoteException("lost reply");
            }
            return NOT_HANDLED;
        });
        try (PairOperation operation = origin.locks.acquire(origin.id(), peer.id(), HASH_1, HASH_2)) {
            assertThrows(RemoteException.class,
                    () -> exchange(origin, syncVia(origin, lostReply), operation.token()));
        }
        assertTrue(origin.isEmpty());
        assertEquals(0, peer.records(), "rolled back by token");
        assertEquals(0, peer.keyMaterial());
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_2, HASH_1));

        String token;
        try (PairOperation operation = origin.locks.acquire(origin.id(), peer.id(), HASH_1, HASH_2)) {
            token = operation.token();
            exchange(origin, origin.sync(), token);
        }
        var originRow = origin.row(HASH_1, HASH_2).orElseThrow();
        var peerRow = peer.row(HASH_2, HASH_1).orElseThrow();
        assertEquals(token, originRow.token());
        assertTrue(ShareConsistency.consistent(originRow, peerRow, origin.id()));
        assertEquals(1, peer.keyMaterial());
    }

    // ---------------------------------------------------------------- helpers

    private static final Object NOT_HANDLED = new Object();

    @FunctionalInterface
    private interface Handler {
        Object handle(String method, Object[] args) throws Exception;
    }

    /** A stub whose calls go to {@code handler} first, then to {@code delegate}. */
    private static NodeCommands intercept(NodeCommands delegate, Handler handler) {
        return (NodeCommands) Proxy.newProxyInstance(NodeCommands.class.getClassLoader(),
                new Class<?>[]{NodeCommands.class}, (proxy, method, args) -> {
                    Object result = handler.handle(method.getName(), args == null ? new Object[0] : args);
                    if (result != NOT_HANDLED) {
                        return result;
                    }
                    try {
                        return method.invoke(delegate, args);
                    } catch (InvocationTargetException ex) {
                        throw ex.getCause();
                    }
                });
    }

    private PeerRecordSync syncVia(SaeNode local, NodeCommands stub) throws Exception {
        RmiManager rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(anyString())).thenReturn(stub);
        return new PeerRecordSync(local.ref, local.map, rmi, cluster.qkd);
    }

    private static void exchange(SaeNode local, PeerRecordSync sync, String token) throws Exception {
        ClientRecord record = SaeFixtures.record(HASH_1, HASH_2, SaeFixtures.PEER_SAE, List.of());
        ProvisionSession.Exchange.Prepared prepared = sync.prepare(record, SaeFixtures.uplink());
        sync.insertPeer(record.withPayload(prepared.keyIds()), token);
        sync.writeOrigin(record.withPayload(prepared.keyIds()), token);
    }
}
