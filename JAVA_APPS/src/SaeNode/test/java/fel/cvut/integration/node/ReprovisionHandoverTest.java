package fel.cvut.integration.node;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.ProvisionCluster.ScriptedOperator;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordAvailability;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.RemoteException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Re-provision handover across three SAE nodes (real SQLite each, real NodeCommandsService over
 * in-process RMI, production ProvisionSession + PeerRecordSync; HSM/QKD/device mocked).
 *
 * <p>Initial state: ORIGIN (sae-1) shares the pair with PEER A (sae-2): origin row (H1,H2)→A,
 * A row (H2,H1)→origin with key material. PEER B (sae-3) then starts a new share that collides
 * with that pair; the operator confirms deletion, the old share is removed on both nodes, and
 * a new share is created.
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
        establishOriginToPeerA(true);
        AtomicBoolean checked = new AtomicBoolean();

        // Device at B (hashes H2,H1) shares with the original origin.
        ProvisionSession.Outcome out = cluster.session(peerB, new ScriptedOperator(true), () -> {
            assertTrue(origin.isEmpty(), "origin must be empty after deleteShare");
            assertTrue(peerA.isEmpty(), "peer A must be empty after deleteShare");
            checked.set(true);
        }).process(SaeFixtures.record(HASH_2, HASH_1, origin.id(), List.of()), SaeFixtures.uplink());

        assertTrue(checked.get(), "deleteShare hook did not run");
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertTrue(peerA.isEmpty());
        assertShared(peerB, HASH_2, HASH_1, origin.id());
        assertShared(origin, HASH_1, HASH_2, peerB.id());
        assertEquals(1, origin.keyMaterial());
        assertEquals(0, peerB.keyMaterial());
    }

    @Test
    void peerBContactsPeerADeletesOldShareAndCreatesNewOne() throws Exception {
        establishOriginToPeerA(true);
        AtomicBoolean checked = new AtomicBoolean();

        // Device at B (hashes H1,H2) shares with peer A; A stores reversed (H2,H1).
        ProvisionSession.Outcome out = cluster.session(peerB, new ScriptedOperator(true), () -> {
            assertTrue(origin.isEmpty(), "origin must be empty after deleteShare");
            assertTrue(peerA.isEmpty(), "peer A must be empty after deleteShare");
            checked.set(true);
        }).process(SaeFixtures.record(HASH_1, HASH_2, peerA.id(), List.of()), SaeFixtures.uplink());

        assertTrue(checked.get(), "deleteShare hook did not run");
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertTrue(origin.isEmpty());
        assertShared(peerB, HASH_1, HASH_2, peerA.id());
        assertShared(peerA, HASH_2, HASH_1, peerB.id());
        assertEquals(1, peerA.keyMaterial());
    }

    @Test
    void handoverAlsoWorksWhileOldShareIsFreshRecordShared() throws Exception {
        establishOriginToPeerA(false);
        ProvisionSession.Outcome out = cluster.session(peerB, new ScriptedOperator(true))
                .process(SaeFixtures.record(HASH_2, HASH_1, origin.id(), List.of()), SaeFixtures.uplink());
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertTrue(peerA.isEmpty());
        assertShared(origin, HASH_1, HASH_2, peerB.id());
    }

    @Test
    void declinedDeleteKeepsOldShareAndLeavesBEmpty() throws Exception {
        establishOriginToPeerA(true);
        // Confirm "generate new keys", then decline "permanently delete".
        ScriptedOperator operator = new ScriptedOperator(true, false);
        ProvisionSession.Outcome out = cluster.session(peerB, operator)
                .process(SaeFixtures.record(HASH_2, HASH_1, origin.id(), List.of()), SaeFixtures.uplink());

        assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out);
        assertEquals(2, operator.confirms.size());
        assertTrue(operator.confirms.get(1).contains("permanently delete"));
        assertTrue(peerB.isEmpty());
        assertEquals(Optional.of(RecordAvailability.ORIGIN_PROVISIONED), origin.state(HASH_1, HASH_2));
        assertEquals(Optional.of(RecordAvailability.ORIGIN_PROVISIONED), peerA.state(HASH_2, HASH_1));
        assertEquals(1, peerA.keyMaterial());
    }

    /**
     * Peer A down during deleteShare: the remote removeRecord is called first and fails, so
     * origin keeps its row and the failure propagates. B rolls back. After A is reachable
     * again the handover succeeds.
     */
    @Test
    void unreachablePeerADuringDeleteShareDeletesNothing() throws Exception {
        establishOriginToPeerA(true);
        cluster.setUnreachable(peerA.id(), true);

        assertThrows(RemoteException.class, () -> cluster.session(peerB, new ScriptedOperator(true))
                .process(SaeFixtures.record(HASH_2, HASH_1, origin.id(), List.of()), SaeFixtures.uplink()));

        assertTrue(peerB.isEmpty());
        assertEquals(Optional.of(RecordAvailability.ORIGIN_PROVISIONED), origin.state(HASH_1, HASH_2));
        assertEquals(Optional.of(RecordAvailability.ORIGIN_PROVISIONED), peerA.state(HASH_2, HASH_1));
        assertEquals(1, peerA.keyMaterial());

        cluster.setUnreachable(peerA.id(), false);
        ProvisionSession.Outcome out = cluster.session(peerB, new ScriptedOperator(true))
                .process(SaeFixtures.record(HASH_2, HASH_1, origin.id(), List.of()), SaeFixtures.uplink());
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertTrue(peerA.isEmpty());
        assertShared(origin, HASH_1, HASH_2, peerB.id());
        assertShared(peerB, HASH_2, HASH_1, origin.id());
    }

    /** Unreachable target (origin) during B's exchange: nothing is deleted anywhere. */
    @Test
    void unreachableOriginLeavesOldShareIntact() throws Exception {
        establishOriginToPeerA(true);
        cluster.setUnreachable(origin.id(), true);
        assertThrows(RemoteException.class, () -> cluster.session(peerB, new ScriptedOperator(true))
                .process(SaeFixtures.record(HASH_2, HASH_1, origin.id(), List.of()), SaeFixtures.uplink()));
        assertTrue(peerB.isEmpty());
        assertEquals(Optional.of(RecordAvailability.ORIGIN_PROVISIONED), origin.state(HASH_1, HASH_2));
        assertEquals(Optional.of(RecordAvailability.ORIGIN_PROVISIONED), peerA.state(HASH_2, HASH_1));
    }

    /**
     * Stale RECORD_SHARED on origin is overwritten by synchronize without a delete prompt.
     * The old counterpart on A is not touched by that path (documented current behavior).
     */
    @Test
    void staleRecordSharedOnOriginIsTakenOverWithoutPrompt() throws Exception {
        establishOriginToPeerA(false);
        age(origin, HASH_1, HASH_2, Instant.now().minus(6, ChronoUnit.MINUTES));
        ScriptedOperator operator = new ScriptedOperator(true);

        ProvisionSession.Outcome out = cluster.session(peerB, operator)
                .process(SaeFixtures.record(HASH_2, HASH_1, origin.id(), List.of()), SaeFixtures.uplink());

        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertEquals(1, operator.confirms.size(), "only the initial generate prompt");
        assertShared(origin, HASH_1, HASH_2, peerB.id());
        assertShared(peerB, HASH_2, HASH_1, origin.id());
        assertEquals(1, peerA.records(), "stale A row is left for its own reclaim");
    }

    private void establishOriginToPeerA(boolean provisioned) throws Exception {
        ProvisionSession.Outcome out = cluster.session(origin, new ScriptedOperator(true))
                .process(SaeFixtures.record(HASH_1, HASH_2, peerA.id(), List.of()), SaeFixtures.uplink());
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        if (provisioned) {
            cluster.markProvisioned(origin, peerA, HASH_1, HASH_2);
        }
        RecordAvailability expected = provisioned ? RecordAvailability.ORIGIN_PROVISIONED : RecordAvailability.RECORD_SHARED;
        assertEquals(Optional.of(expected), origin.state(HASH_1, HASH_2));
        assertEquals(Optional.of(expected), peerA.state(HASH_2, HASH_1));
        assertEquals(1, peerA.keyMaterial());
        assertTrue(peerB.isEmpty());
    }

    private static void assertShared(SaeNode node, String h1, String h2, String counterpart) {
        var meta = node.map.get(h1, h2).orElseThrow(() -> new AssertionError(node.id() + " has no row"));
        assertEquals(RecordAvailability.RECORD_SHARED, meta.recordAvailability());
        assertEquals(counterpart, meta.saeId());
    }

    private static void age(SaeNode node, String h1, String h2, Instant when) throws Exception {
        try (Connection connection = node.dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "UPDATE client_record_state SET date_of_creation = ? "
                             + "WHERE client_hash1 = ? AND client_hash2 = ?")) {
            statement.setString(1, when.toString());
            statement.setString(2, h1);
            statement.setString(3, h2);
            assertEquals(1, statement.executeUpdate());
        }
    }
}
