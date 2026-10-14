package fel.cvut.harness;

import fel.cvut.node.PeerRecordSync;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.qkd.Qkd014Client;

import java.util.List;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Shared origin/peer SQLite maps, mock QKD, and peer {@link NodeCommandsService} for PeerRecordSync tests.
 */
public final class PeerRecordSyncHarness {

    public final AtomicRecordStateMap originMap;
    public final AtomicRecordStateMap peerMap;
    public final NodeCommandsService peerService;
    public final Qkd014Client qkd;
    public final RmiManager rmi;

    private final SaeSqliteExtension sqlite;

    private PeerRecordSyncHarness(SaeSqliteExtension sqlite) throws Exception {
        this.sqlite = sqlite;
        originMap = SaeFixtures.stateMap(ORIGIN_SAE, sqlite.origin());
        peerMap = SaeFixtures.stateMap(PEER_SAE, sqlite.peer());
        qkd = SaeFixtures.mockQkd();
        peerService = SaeFixtures.commands(
                SaeFixtures.peerRef(),
                sqlite.peer(),
                qkd,
                JceAesGcm.mockHsm()
        );
        rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(peerService);
    }

    /** Builds a harness wired to the given SQLite extension. */
    public static PeerRecordSyncHarness open(SaeSqliteExtension sqlite) throws Exception {
        return new PeerRecordSyncHarness(sqlite);
    }

    /** Creates a PeerRecordSync for the origin map using this harness's RMI and QKD. */
    public PeerRecordSync sync() {
        return sync(originMap);
    }

    /** Creates a PeerRecordSync for {@code origin} using this harness's RMI and QKD. */
    public PeerRecordSync sync(AtomicRecordStateMap origin) {
        return new PeerRecordSync(SaeFixtures.originRef(), origin, rmi, qkd);
    }

    /** Origin ClientRecord for the standard HASH_1/HASH_2 pair. */
    public static ClientRecord originRecord() {
        return SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of());
    }

    /** Reserves the origin pair in SYNCHRONIZATION. */
    public void reserveOrigin() {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
    }

    /**
     * Asserts both DBs have no row for the pair and no key material, then proves the pair can be
     * reserved again on each side.
     */
    public void assertBothEmptyAndReinsertable() {
        assertTrue(originMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(peerMap.get(HASH_1, HASH_2).isEmpty());
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty());
        assertEquals(0, keyMaterialCount());
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        originMap.tryDelete(HASH_1, HASH_2, ORIGIN_SAE);
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                peerMap.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), PEER_SAE)
        );
        peerMap.tryDelete(HASH_2, HASH_1, PEER_SAE);
    }

    private long keyMaterialCount() {
        try {
            return SaeFixtures.countKeyMaterial(sqlite.origin())
                    + SaeFixtures.countKeyMaterial(sqlite.peer());
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}
