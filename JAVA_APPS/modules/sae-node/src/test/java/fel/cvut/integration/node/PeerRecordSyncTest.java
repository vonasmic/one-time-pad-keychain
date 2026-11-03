package fel.cvut.integration.node;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.PeerRecordSync;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.pairlock.PairOperation;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.List;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

/** PeerRecordSync over in-process RMI against a real peer service, under real pair locks. */
@Timeout(60)
@Tag("integration")
class PeerRecordSyncTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private ProvisionCluster cluster;
    private SaeNode origin;
    private SaeNode peer;

    @BeforeEach
    void setUp() throws Exception {
        cluster = new ProvisionCluster(SQLITE);
        origin = cluster.origin();
        peer = cluster.peerA();
    }

    @AfterEach
    void tearDown() {
        cluster.close();
    }

    @Test
    void successfulExchangeWritesBothSidesWithOneToken() throws Exception {
        String token = exchange(origin.sync());
        var originRow = origin.row(HASH_1, HASH_2).orElseThrow();
        var peerRow = peer.row(HASH_2, HASH_1).orElseThrow();
        assertEquals(token, originRow.token());
        assertEquals(token, peerRow.token());
        assertEquals(AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE, peerRow.recordAvailability());
        assertEquals(SaeFixtures.padPlain(), originRow.padPlainLen());
        assertEquals(SaeFixtures.padPlain(), peerRow.padPlainLen());
        assertEquals(1, peer.keyMaterial());
    }

    @Test
    void originWriteFailureRemovesThePeerRowByToken() throws Exception {
        AtomicRecordStateMap failing = spy(origin.map);
        doThrow(new IllegalStateException("Failed to write origin record."))
                .when(failing).writeOrigin(anyString(), any());
        PeerRecordSync sync = new PeerRecordSync(origin.ref, failing, origin.rmi, cluster.qkd);
        assertThrows(IllegalStateException.class, () -> exchange(sync));
        assertTrue(origin.isEmpty());
        assertTrue(peer.isEmpty());
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peer.pairFree(HASH_1, HASH_2));
        exchange(origin.sync());
        assertEquals(1, peer.records());
    }

    private String exchange(PeerRecordSync sync) throws Exception {
        ClientRecord record = SaeFixtures.record(HASH_1, HASH_2, peer.id(), List.of());
        try (PairOperation operation = origin.locks.acquire(origin.id(), peer.id(), HASH_1, HASH_2)) {
            ProvisionSession.Exchange.Prepared prepared = sync.prepare(record, SaeFixtures.uplink());
            ClientRecord completed = record.withPayload(prepared.keyIds());
            sync.insertPeer(completed, operation.token());
            try {
                sync.writeOrigin(completed, operation.token());
            } catch (Exception ex) {
                // What closing an incomplete Delivery does.
                sync.removePeer(completed, operation.token());
                throw ex;
            }
            return operation.token();
        }
    }
}
