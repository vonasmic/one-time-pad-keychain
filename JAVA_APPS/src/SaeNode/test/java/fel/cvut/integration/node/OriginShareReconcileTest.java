package fel.cvut.integration.node;

import fel.cvut.db.SharedKeyMaterialRepository;
import fel.cvut.harness.AsCaller;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.Tag;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Timeout(60)
@Tag("integration")
class OriginShareReconcileTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap originMap;
    private AtomicRecordStateMap peerMap;
    private NodeCommandsService peerService;
    /** Peer service as called by the origin SAE (authenticated caller ORIGIN_SAE). */
    private NodeCommands peerAsOrigin;

    @BeforeEach
    void setUp() {
        originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
        peerService = new NodeCommandsService(
                SaeFixtures.peerRef(),
                peerMap,
                SaeFixtures.mockQkd(),
                SaeFixtures.keyStore(SQLITE.peer(), JceAesGcm.mockHsm())
        );
        peerAsOrigin = AsCaller.bind(ORIGIN_SAE, peerService);
    }

    @Test
    void freshSharedRejectsSynchronize() throws Exception {
        reserveAndFinish(originMap, HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE);
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);

        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.NOT_INSERTED,
                peerAsOrigin.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability()
        );
    }

    @Test
    void originProvisionedRejectsSynchronize() throws Exception {
        reserveAndFinish(originMap, HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE);
        assertTrue(originMap.markOriginProvisioned(HASH_1, HASH_2));
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);
        assertTrue(peerAsOrigin.markOriginProvisioned(HASH_2, HASH_1));

        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.ORIGIN_PROVISIONED,
                peerAsOrigin.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED,
                peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability()
        );
    }

    @Test
    void staleSharedReclaimsPeerAndDeletesKeys() throws Exception {
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);
        try (Connection connection = SQLITE.peer().getConnection()) {
            new SharedKeyMaterialRepository().upsert(
                    connection, HASH_2, HASH_1, JceAesGcm.encrypt("pad".getBytes()));
        }
        age(SQLITE.peer(), HASH_2, HASH_1, Instant.now().minus(6, ChronoUnit.MINUTES));

        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                peerAsOrigin.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SYNCHRONIZATION,
                peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability()
        );
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.peer()));
    }

    @Test
    void deleteShareRemovesOriginAndPeer() throws Exception {
        reserveAndFinish(originMap, HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE);
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);
        RmiManager rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(peerAsOrigin);
        NodeCommandsService originService = new NodeCommandsService(
                SaeFixtures.originRef(),
                originMap,
                SaeFixtures.mockQkd(),
                SaeFixtures.keyStore(SQLITE.origin(), JceAesGcm.mockHsm()),
                rmi);
        AsCaller.run(ORIGIN_SAE, () -> originService.deleteShare(HASH_1, HASH_2));
        assertTrue(originMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty());
    }

    private static void reserveAndFinish(
            AtomicRecordStateMap map, String h1, String h2, String target, String issuer
    ) {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                map.synchronize(SaeFixtures.header(h1, h2, target), issuer)
        );
        assertTrue(map.lockFetch(h1, h2, issuer));
        assertTrue(map.finishRecordInsert(h1, h2));
    }

    private static void age(javax.sql.DataSource dataSource, String h1, String h2, Instant when) throws Exception {
        try (Connection connection = dataSource.getConnection();
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
