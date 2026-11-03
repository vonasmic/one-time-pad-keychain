package fel.cvut.harness;

import fel.cvut.node.NodeRef;
import fel.cvut.node.PeerRecordSync;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.RmiRemoteRecords;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.pairlock.PairLocks;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.se.SeKemFill;

import javax.sql.DataSource;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.UnaryOperator;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Three SAE nodes (origin / peer / other), each with its own real SQLite DB, pair-lock registry,
 * a real {@link NodeCommandsService} exported over {@link InProcessRmi} through
 * {@link TestRmiNetwork}, and a per-node mock {@link RmiManager} whose stubs carry that node's SAE
 * ID as the authenticated RMI caller. {@link #session} builds a production
 * {@link ProvisionSession} wired as {@code Node#provisionSession()} wires it (Records = local map
 * + key store, Exchange = PeerRecordSync, RemoteRecords = {@link RmiRemoteRecords}, Locks =
 * {@link PairLocks}). HSM, QKD and SeKemFill (device downlink) are mocks.
 */
public final class ProvisionCluster implements AutoCloseable {

    public static final byte[] DOWNLINK = {7, 7, 7};

    public final Qkd014Client qkd;
    /** Per-caller in-process RMI (each node's calls carry its own SAE ID, as pinned TLS does). */
    public final TestRmiNetwork net = new TestRmiNetwork();
    public final SeKemFill kemFill;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "test-pair-lock-renewal");
        thread.setDaemon(true);
        return thread;
    });
    private final Map<String, SaeNode> nodes = new LinkedHashMap<>();

    public final class SaeNode {
        public final NodeRef ref;
        public final DataSource dataSource;
        public final PairLockRegistry registry;
        public final AtomicRecordStateMap map;
        public final SharedKeyMaterialStore store;
        public final NodeCommandsService service;
        /** This node's view of the network: stubs it obtains carry its SAE ID as the caller. */
        public final RmiManager rmi;
        public final PairLocks locks;

        SaeNode(NodeRef ref, DataSource dataSource) throws Exception {
            this.ref = ref;
            this.dataSource = dataSource;
            this.registry = SaeFixtures.registry(dataSource);
            this.map = SaeFixtures.stateMap(ref.getNodeId(), dataSource);
            this.store = SaeFixtures.keyStore(dataSource, JceAesGcm.mockHsm());
            this.rmi = net.rmiFor(ref.getNodeId());
            this.service = new NodeCommandsService(ref, map, qkd, store);
            this.locks = new PairLocks(ref.getNodeId(), registry, rmi::connectBySaeId,
                    scheduler, PairLocks.RENEW_INTERVAL);
            net.register(ref.getNodeId(), service);
        }

        public String id() {
            return ref.getNodeId();
        }

        public PeerRecordSync sync() {
            return new PeerRecordSync(ref, map, rmi, qkd);
        }

        public RmiRemoteRecords remote() {
            return new RmiRemoteRecords(id(), map, rmi::connectBySaeId);
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

        public Optional<AtomicRecordStateMap.RecordMetadata> row(String h1, String h2) {
            return map.get(h1, h2);
        }

        /** {@code true} when nobody holds a live lease on the pair here. */
        public boolean pairFree(String h1, String h2) {
            return registry.lease(fel.cvut.node.pairlock.PairKey.of(h1, h2)).isEmpty();
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
        private final List<Runnable> onConfirm = new ArrayList<>();

        public ScriptedOperator(Boolean... answers) {
            this.answers = new ArrayDeque<>(List.of(answers));
        }

        /** Runs {@code action} while the operator is asked confirm number {@code index} (0-based). */
        public ScriptedOperator during(int index, Runnable action) {
            while (onConfirm.size() <= index) {
                onConfirm.add(null);
            }
            onConfirm.set(index, action);
            return this;
        }

        @Override
        public boolean confirm(String message) throws IOException {
            int index = confirms.size();
            confirms.add(message);
            if (index < onConfirm.size() && onConfirm.get(index) != null) {
                onConfirm.get(index).run();
            }
            return answers.isEmpty() || answers.poll();
        }

        @Override
        public void notify(String message) {
            notifies.add(message);
        }
    }

    public ProvisionSession session(SaeNode local, ProvisionSession.Operator operator) {
        return session(local, operator, UnaryOperator.identity());
    }

    /** Mirrors {@code Node#provisionSession()}; {@code wrapRemote} may decorate the RemoteRecords. */
    public ProvisionSession session(
            SaeNode local, ProvisionSession.Operator operator, UnaryOperator<ProvisionSession.RemoteRecords> wrapRemote) {
        return session(local, operator, wrapRemote, List.of());
    }

    public ProvisionSession session(
            SaeNode local, ProvisionSession.Operator operator,
            UnaryOperator<ProvisionSession.RemoteRecords> wrapRemote, List<RmiManager.SaeNode> saeNodes) {
        ProvisionSession.Records records = new ProvisionSession.Records() {
            @Override
            public Optional<AtomicRecordStateMap.RecordMetadata> get(String clientHash1, String clientHash2) {
                return local.map.get(clientHash1, clientHash2);
            }

            @Override
            public Optional<List<String>> readPayload(String clientHash1, String clientHash2) throws IOException {
                return local.store.readPayload(clientHash1, clientHash2);
            }
        };
        return new ProvisionSession(
                local.id(), records, local.sync(), operator, wrapRemote.apply(local.remote()),
                local.locks::acquire, kemFill, saeNodes);
    }

    /**
     * What {@code Node#deliver} does after the device sent {@code SE_OK}: the delivery writes the origin row
     * (new share) under the gap guard and is closed (both locks released).
     *
     * @return {@code true} when the share may be reported complete
     */
    public static boolean deviceAcked(ProvisionSession.Outcome outcome) {
        ProvisionSession.Delivery delivery = switch (outcome) {
            case ProvisionSession.Outcome.Generated generated -> generated.delivery();
            case ProvisionSession.Outcome.Existing existing -> existing.delivery();
            default -> throw new IllegalArgumentException("no delivery in " + outcome);
        };
        try (delivery) {
            delivery.afterDeviceAck();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
        net.close();
    }
}
