package fel.cvut.harness;

import fel.cvut.node.NodeCommands;
import fel.cvut.node.NodeRef;
import fel.cvut.node.PeerRecordSync;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.se.SeKemFill;

import javax.sql.DataSource;
import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Three SAE nodes (origin / peer / other), each with its own real SQLite DB, a real
 * {@link NodeCommandsService} exported over {@link InProcessRmi} through {@link TestRmiNetwork},
 * and a per-node mock {@link RmiManager} whose stubs carry that node's SAE ID as the
 * authenticated RMI caller. {@link #session} builds a
 * production {@link ProvisionSession} wired the same way {@code Node#provisionSession()}
 * wires it (Records = local map + key store, Exchange = PeerRecordSync, RemoteRecords = RMI).
 * HSM, QKD and SeKemFill (device downlink) are mocks.
 */
public final class ProvisionCluster implements AutoCloseable {

    public static final byte[] DOWNLINK = {7, 7, 7};

    public final Qkd014Client qkd;
    /** Per-caller in-process RMI (each node's calls carry its own SAE ID, as pinned TLS does). */
    public final TestRmiNetwork net = new TestRmiNetwork();
    public final SeKemFill kemFill;
    private final Map<String, SaeNode> nodes = new LinkedHashMap<>();

    public final class SaeNode {
        public final NodeRef ref;
        public final DataSource dataSource;
        public final AtomicRecordStateMap map;
        public final SharedKeyMaterialStore store;
        public final NodeCommandsService service;
        /** This node's view of the network: stubs it obtains carry its SAE ID as the caller. */
        public final RmiManager rmi;

        SaeNode(NodeRef ref, DataSource dataSource) throws Exception {
            this.ref = ref;
            this.dataSource = dataSource;
            this.map = SaeFixtures.stateMap(ref.getNodeId(), dataSource);
            this.store = SaeFixtures.keyStore(dataSource, JceAesGcm.mockHsm());
            this.rmi = net.rmiFor(ref.getNodeId());
            this.service = new NodeCommandsService(ref, map, qkd, store, rmi);
            net.register(ref.getNodeId(), service);
        }

        public String id() {
            return ref.getNodeId();
        }

        public PeerRecordSync sync() {
            return new PeerRecordSync(ref, map, rmi, qkd);
        }

        public long records() throws Exception {
            return SaeFixtures.countRecords(dataSource);
        }

        public long keyMaterial() throws Exception {
            return SaeFixtures.countKeyMaterial(dataSource);
        }

        public boolean isEmpty() throws Exception {
            return records() == 0 && keyMaterial() == 0;
        }

        public Optional<AtomicRecordStateMap.RecordAvailability> state(String h1, String h2) {
            return map.get(h1, h2).map(AtomicRecordStateMap.RecordMetadata::recordAvailability);
        }
    }

    public ProvisionCluster(SaeSqliteExtension sqlite) throws Exception {
        qkd = SaeFixtures.mockQkd();
        kemFill = mock(SeKemFill.class);
        when(kemFill.buildDownlink(any(), anyList(), anyByte(), anyInt())).thenReturn(DOWNLINK);
        nodes.put(SaeFixtures.ORIGIN_SAE, new SaeNode(SaeFixtures.originRef(), sqlite.origin()));
        nodes.put(SaeFixtures.PEER_SAE, new SaeNode(SaeFixtures.peerRef(), sqlite.peer()));
        nodes.put(SaeFixtures.OTHER_SAE, new SaeNode(SaeFixtures.otherRef(), sqlite.other()));
    }

    public SaeNode origin() {
        return nodes.get(SaeFixtures.ORIGIN_SAE);
    }

    public SaeNode peerA() {
        return nodes.get(SaeFixtures.PEER_SAE);
    }

    public SaeNode peerB() {
        return nodes.get(SaeFixtures.OTHER_SAE);
    }

    public void setUnreachable(String saeId, boolean down) {
        net.setUnreachable(saeId, down);
    }

    /** Scripted operator: answers confirms in order (default {@code true} once exhausted). */
    public static final class ScriptedOperator implements ProvisionSession.Operator {
        private final Deque<Boolean> answers;
        public final List<String> confirms = new ArrayList<>();
        public final List<String> notifies = new ArrayList<>();

        public ScriptedOperator(Boolean... answers) {
            this.answers = new ArrayDeque<>(List.of(answers));
        }

        @Override
        public boolean confirm(String message) {
            confirms.add(message);
            return answers.isEmpty() || answers.poll();
        }

        @Override
        public void notify(String message) {
            notifies.add(message);
        }
    }

    /** Hook run right after {@link ProvisionSession.RemoteRecords#deleteShare} returns. */
    public interface AfterDeleteShare {
        void run() throws Exception;
    }

    public ProvisionSession session(SaeNode local, ProvisionSession.Operator operator) {
        return session(local, operator, () -> { });
    }

    /** Mirrors {@code Node#provisionSession()} using test-visible components. */
    public ProvisionSession session(SaeNode local, ProvisionSession.Operator operator, AfterDeleteShare hook) {
        ProvisionSession.Records records = new ProvisionSession.Records() {
            @Override
            public AtomicRecordStateMap.SynchronizeOutcome synchronize(
                    ClientRecord.ClientHeader header, String localSaeId) {
                return local.map.synchronize(header, localSaeId);
            }

            @Override
            public Optional<AtomicRecordStateMap.RecordMetadata> get(String clientHash1, String clientHash2) {
                return local.map.get(clientHash1, clientHash2);
            }

            @Override
            public void tryDelete(String clientHash1, String clientHash2, String issuingSaeId, String reason) {
                local.map.tryDelete(clientHash1, clientHash2, issuingSaeId);
            }

            @Override
            public void forceDeleteLocal(String clientHash1, String clientHash2, String reason) {
                local.map.forceDelete(clientHash1, clientHash2);
            }

            @Override
            public Optional<List<String>> readPayload(String clientHash1, String clientHash2) throws IOException {
                return local.store.readPayload(clientHash1, clientHash2);
            }

            @Override
            public void removePayload(String clientHash1, String clientHash2) throws IOException {
                local.store.remove(clientHash1, clientHash2);
            }
        };
        ProvisionSession.RemoteRecords remote = new ProvisionSession.RemoteRecords() {
            @Override
            public void forceDelete(String saeId, String clientHash1, String clientHash2)
                    throws RemoteException, NotBoundException {
                local.rmi.connectBySaeId(saeId).removeRecord(clientHash2, clientHash1);
            }

            @Override
            public void deleteShare(String saeId, String clientHash1, String clientHash2)
                    throws RemoteException, NotBoundException {
                NodeCommands node = local.rmi.connectBySaeId(saeId);
                node.deleteShare(clientHash2, clientHash1);
                try {
                    hook.run();
                } catch (RuntimeException | Error ex) {
                    throw ex;
                } catch (Exception ex) {
                    throw new IllegalStateException(ex);
                }
            }

            @Override
            public AtomicRecordStateMap.RecordMetadata get(String saeId, String clientHash1, String clientHash2)
                    throws RemoteException, NotBoundException {
                if (saeId.equals(local.id())) {
                    return local.map.get(clientHash2, clientHash1).orElse(null);
                }
                return local.rmi.connectBySaeId(saeId).getRecordMetadata(clientHash2, clientHash1);
            }
        };
        return new ProvisionSession(
                local.id(), records, local.sync()::completeNewExchange, operator, remote, kemFill);
    }

    /** Origin-side ack: peer first (reversed hashes), then origin — same order as Node. */
    public void markProvisioned(SaeNode originNode, SaeNode peerNode, String h1, String h2) {
        if (!peerNode.map.markOriginProvisioned(h2, h1) || !originNode.map.markOriginProvisioned(h1, h2)) {
            throw new IllegalStateException("markOriginProvisioned failed");
        }
    }

    @Override
    public void close() {
        net.close();
    }
}
