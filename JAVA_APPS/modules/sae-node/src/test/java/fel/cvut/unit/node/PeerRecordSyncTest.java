package fel.cvut.unit.node;

import fel.cvut.harness.PeerRecordSyncHarness;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.qkd.Qkd014ClientException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.rmi.RemoteException;
import java.util.List;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

/**
 * PeerRecordSync against a real peer service and two SQLite maps: prepare only talks to the
 * KME; insertPeer writes the peer row (before the device transfer), writeOrigin the origin row
 * (after the device ack), and removePeer deletes the peer row by token when the share is not
 * completed.
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
    void prepareFetchesKeysAndWritesNothing() throws Exception {
        ProvisionSession.Exchange.Prepared prepared =
                h.sync().prepare(PeerRecordSyncHarness.originRecord(), SaeFixtures.uplink());
        assertFalse(prepared.keyIds().isEmpty());
        assertFalse(prepared.keyMaterial().isEmpty());
        assertEquals(0, SaeFixtures.countRecords(SQLITE.origin()) + SaeFixtures.countRecords(SQLITE.peer()));
    }

    @Test
    void insertPeerThenWriteOriginWritesBothRowsWithOneToken() throws Exception {
        boolean[] originEmptyAtPeerInsert = {false};
        when(h.rmi.connectBySaeId(PEER_SAE)).thenReturn(intercept(h.peer, "insert", () ->
                originEmptyAtPeerInsert[0] = h.originMap.get(HASH_1, HASH_2).isEmpty()));
        String token = h.lockBoth();

        h.sync().insertPeer(PeerRecordSyncHarness.originRecord(), token);
        assertTrue(h.originMap.get(HASH_1, HASH_2).isEmpty(), "the origin row waits for the device ack");
        h.sync().writeOrigin(PeerRecordSyncHarness.originRecord(), token);

        assertTrue(originEmptyAtPeerInsert[0], "remote first");
        assertEquals(token, h.originMap.get(HASH_1, HASH_2).orElseThrow().token());
        assertEquals(PEER_SAE, h.originMap.get(HASH_1, HASH_2).orElseThrow().saeId());
        assertEquals(token, h.peerMap.get(HASH_2, HASH_1).orElseThrow().token());
        assertEquals(ORIGIN_SAE, h.peerMap.get(HASH_2, HASH_1).orElseThrow().saeId());
        assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.origin()));
    }

    @Test
    void connectFailureWritesNothing() throws Exception {
        doThrow(new RemoteException("peer down")).when(h.rmi).connectBySaeId(anyString());
        String token = h.lockBoth();
        assertThrows(RemoteException.class, () -> h.sync().insertPeer(PeerRecordSyncHarness.originRecord(), token));
        h.releaseBoth(token);
        doReturn(h.peer).when(h.rmi).connectBySaeId(PEER_SAE);
        h.assertBothEmptyAndReinsertable();
    }

    @Test
    void lostReplyAfterThePeerCommittedRemovesThePeerRowByToken() throws Exception {
        when(h.rmi.connectBySaeId(PEER_SAE)).thenReturn(failAfter(h.peer, "insert"));
        String token = h.lockBoth();
        assertThrows(RemoteException.class, () -> h.sync().insertPeer(PeerRecordSyncHarness.originRecord(), token));
        h.releaseBoth(token);
        when(h.rmi.connectBySaeId(PEER_SAE)).thenReturn(h.peer);
        h.assertBothEmptyAndReinsertable();
    }

    @Test
    void peerWithoutTheLeaseRefusesTheInsert() throws Exception {
        String token = h.lockBoth();
        h.peerMap.registry().release(PairKey.of(HASH_1, HASH_2), token);
        assertThrows(PairLockLostException.class, () -> h.sync().insertPeer(PeerRecordSyncHarness.originRecord(), token));
        assertTrue(h.originMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(h.peerMap.get(HASH_2, HASH_1).isEmpty());
    }

    @Test
    void originWriteFailureThenRemovePeerDeletesThePeerRowByToken() throws Exception {
        String token = h.lockBoth();
        h.sync().insertPeer(PeerRecordSyncHarness.originRecord(), token);
        // The origin lost its own lease while the device was written.
        h.originMap.registry().release(PairKey.of(HASH_1, HASH_2), token);
        assertThrows(PairLockLostException.class, () -> h.sync().writeOrigin(PeerRecordSyncHarness.originRecord(), token));
        assertTrue(h.peerMap.get(HASH_2, HASH_1).isPresent());
        h.sync().removePeer(PeerRecordSyncHarness.originRecord(), token);
        assertTrue(h.originMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(h.peerMap.get(HASH_2, HASH_1).isEmpty(), "peer row rolled back by token");
        h.releaseBoth(token);
        when(h.rmi.connectBySaeId(PEER_SAE)).thenReturn(h.peer);
        h.assertBothEmptyAndReinsertable();
    }

    @Test
    void qkdFailureInPrepareWritesNothing() throws Exception {
        when(h.qkd.getKey(any(), any(), nullable(Integer.class)))
                .thenThrow(new Qkd014ClientException("kme down", 503, null));
        assertThrows(Exception.class, () -> h.sync().prepare(PeerRecordSyncHarness.originRecord(), SaeFixtures.uplink()));
        h.assertBothEmptyAndReinsertable();
    }

    private static NodeCommands failAfter(NodeCommands target, String methodName) {
        return (NodeCommands) Proxy.newProxyInstance(NodeCommands.class.getClassLoader(),
                new Class<?>[]{NodeCommands.class}, (proxy, method, args) -> {
                    Object result = invoke(target, method, args);
                    if (method.getName().equals(methodName)) {
                        throw new RemoteException("reply lost after " + methodName);
                    }
                    return result;
                });
    }

    private static NodeCommands intercept(NodeCommands target, String methodName, Runnable before) {
        return intercept(target, methodName, before, () -> { });
    }

    private static NodeCommands intercept(NodeCommands target, String methodName, Runnable before, Runnable after) {
        return (NodeCommands) Proxy.newProxyInstance(NodeCommands.class.getClassLoader(),
                new Class<?>[]{NodeCommands.class}, (proxy, method, args) -> {
                    boolean match = method.getName().equals(methodName);
                    if (match) {
                        before.run();
                    }
                    Object result = invoke(target, method, args);
                    if (match) {
                        after.run();
                    }
                    return result;
                });
    }

    private static Object invoke(NodeCommands target, java.lang.reflect.Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException ex) {
            throw ex.getCause();
        }
    }

    @SuppressWarnings("unused")
    private static final List<String> UNUSED = List.of();
}
