package fel.cvut.node;

import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(60)
class OriginShareReconcileTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap originMap;
    private AtomicRecordStateMap peerMap;
    private NodeCommandsService peerService;

    @BeforeEach
    void setUp() {
        originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
        peerService = new NodeCommandsService(
                SaeFixtures.peerRef(),
                peerMap,
                SaeFixtures.mockQkd(),
                SaeFixtures.keyStore(SQLITE.peer(), JceAesGcm.mockHsm()),
                originAccess()
        );
    }

    @Test
    void provisionedOriginKeepsPeerShare() throws Exception {
        reserveAndFinish(originMap, HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE);
        assertTrue(originMap.markProvisioned(HASH_1, HASH_2));
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);

        assertFalse(peerService.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_PROVISIONED,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE,
                peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability()
        );
    }

    @Test
    void freshFetchingOriginLeavesPeerShare() throws Exception {
        reserveAndLock(originMap, HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE);
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);

        assertFalse(peerService.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_FETCHING_STARTED,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
        assertTrue(peerMap.get(HASH_2, HASH_1).isPresent());
    }

    @Test
    void staleFetchingOriginDeletesBoth() throws Exception {
        reserveAndLock(originMap, HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE);
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);
        age(SQLITE.origin(), HASH_1, HASH_2, Instant.now().minus(3, ChronoUnit.MINUTES));

        assertFalse(peerService.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertTrue(originMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty());
    }

    @Test
    void freshSynchronizationDeletesPeerOnly() throws Exception {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);

        assertFalse(peerService.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SYNCHRONIZATION,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty());
    }

    @Test
    void missingOriginDeletesPeer() throws Exception {
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);

        assertFalse(peerService.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty());
    }

    @Test
    void unreachableOriginLeavesPeerShare() throws Exception {
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);
        NodeCommandsService unreachablePeer = new NodeCommandsService(
                SaeFixtures.peerRef(),
                peerMap,
                SaeFixtures.mockQkd(),
                SaeFixtures.keyStore(SQLITE.peer(), JceAesGcm.mockHsm()),
                OriginShareAccess.unreachable()
        );

        assertFalse(unreachablePeer.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertTrue(peerMap.get(HASH_2, HASH_1).isPresent());
    }

    @Test
    void staleAvailableOriginDeletesBoth() throws Exception {
        reserveAndFinish(originMap, HASH_1, HASH_2, PEER_SAE, ORIGIN_SAE);
        reserveAndFinish(peerMap, HASH_2, HASH_1, ORIGIN_SAE, ORIGIN_SAE);
        age(SQLITE.origin(), HASH_1, HASH_2, Instant.now().minus(3, ChronoUnit.MINUTES));

        assertFalse(peerService.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertTrue(originMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty());
    }

    private OriginShareAccess originAccess() {
        return new OriginShareAccess() {
            @Override
            public AtomicRecordStateMap.RecordMetadata get(String saeId, String clientHash1, String clientHash2) {
                return originMap.get(clientHash1, clientHash2).orElse(null);
            }

            @Override
            public AtomicRecordStateMap.RecordMetadata remove(String saeId, String clientHash1, String clientHash2) {
                return originMap.forceDelete(clientHash1, clientHash2).orElse(null);
            }
        };
    }

    private static void reserveAndLock(
            AtomicRecordStateMap map, String h1, String h2, String target, String issuer
    ) {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                map.synchronize(SaeFixtures.header(h1, h2, target), issuer)
        );
        assertTrue(map.lockFetch(h1, h2, issuer));
    }

    private static void reserveAndFinish(
            AtomicRecordStateMap map, String h1, String h2, String target, String issuer
    ) {
        reserveAndLock(map, h1, h2, target, issuer);
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
