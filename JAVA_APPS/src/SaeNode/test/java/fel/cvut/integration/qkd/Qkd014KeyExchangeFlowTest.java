package fel.cvut.integration.qkd;

import fel.cvut.harness.AsCaller;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.MockKme;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.PeerRecordSync;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.tls.SoftwareTls;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import javax.net.ssl.SSLContext;
import java.util.List;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Origin SAE requests keys from the KME (enc_keys) through a real {@link Qkd014Client}, the peer
 * SAE resolves the same key IDs (dec_keys) through its own client, and both SQLite databases end
 * up with a RECORD_SHARED row; the peer stores the identical key material (sealed).
 */
@Tag("integration")
@Timeout(120)
class Qkd014KeyExchangeFlowTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private MockKme kme;
    private AtomicRecordStateMap originMap;
    private AtomicRecordStateMap peerMap;
    private SharedKeyMaterialStore peerStore;
    private PeerRecordSync sync;

    @BeforeEach
    void setUp() throws Exception {
        kme = new MockKme();
        SSLContext plain = SSLContext.getInstance("TLS");
        plain.init(null, null, null);
        Qkd014Client originQkd = new Qkd014Client(kme.baseUrl(), plain, SoftwareTls.TlsProfile.CLASSICAL);
        Qkd014Client peerQkd = new Qkd014Client(kme.baseUrl(), plain, SoftwareTls.TlsProfile.CLASSICAL);

        originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
        peerStore = SaeFixtures.keyStore(SQLITE.peer(), JceAesGcm.mockHsm());
        NodeCommandsService peerService = new NodeCommandsService(
                SaeFixtures.peerRef(), peerMap, peerQkd, peerStore, mock(RmiManager.class));
        RmiManager rmi = mock(RmiManager.class);
        // the peer sees the origin as the authenticated RMI caller (F-01)
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(AsCaller.bind(ORIGIN_SAE, peerService));
        sync = new PeerRecordSync(SaeFixtures.originRef(), originMap, rmi, originQkd);
    }

    @AfterEach
    void tearDown() {
        kme.close();
    }

    @Test
    void keysFlowFromKmeIntoBothDatabases() throws Exception {
        reserveOrigin();

        ProvisionSession.Exchange.Result result = sync.completeNewExchange(originRecord(), SaeFixtures.uplink());

        ProvisionSession.Exchange.Result.Generated generated =
                assertInstanceOf(ProvisionSession.Exchange.Result.Generated.class, result);
        List<String> originMaterial = generated.keyMaterial();
        assertTrue(!originMaterial.isEmpty());
        assertTrue(kme.encCalls.get() >= 1);
        assertTrue(kme.decCalls.get() >= 1);
        assertEquals(0, kme.issuedCount(), "every issued key ID must have been consumed by the peer");

        assertEquals(AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability());
        AtomicRecordStateMap.RecordMetadata peerRow = peerMap.get(HASH_2, HASH_1).orElseThrow();
        assertEquals(AtomicRecordStateMap.RecordAvailability.RECORD_SHARED, peerRow.recordAvailability());
        assertEquals(ORIGIN_SAE, peerRow.saeId());
        assertEquals(ORIGIN_SAE, peerRow.issuingSaeId());

        List<String> peerMaterial = peerStore.readPayload(HASH_2, HASH_1).orElseThrow();
        assertEquals(originMaterial, peerMaterial, "both SAEs must hold the same QKD key material");

        assertTrue(originMap.markOriginProvisioned(HASH_1, HASH_2));
        assertTrue(peerMap.markOriginProvisioned(HASH_2, HASH_1));
        assertEquals(AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED,
                peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability());
    }

    @Test
    void largeKeyIdListIsBatchedThroughPost() throws Exception {
        kme.keySizeBits = 64;       // small pool keys and no packing -> many key IDs per pad
        kme.maxKeySizeBits = 64;
        kme.maxPerRequest = 2;
        reserveOrigin();

        ProvisionSession.Exchange.Result result = sync.completeNewExchange(originRecord(), SaeFixtures.uplink());

        List<String> originMaterial =
                assertInstanceOf(ProvisionSession.Exchange.Result.Generated.class, result).keyMaterial();
        assertTrue(originMaterial.size() > 2, "expected several keys, got " + originMaterial.size());
        assertTrue(kme.decCalls.get() > 1, "peer must resolve the IDs in several dec_keys batches");
        assertEquals(originMaterial, peerStore.readPayload(HASH_2, HASH_1).orElseThrow());
        assertEquals(0, kme.issuedCount());
    }

    @Test
    void peerKmeRefusalRollsBackBothSides() throws Exception {
        kme.failDecKeysWith = 400;
        reserveOrigin();

        assertThrows(java.rmi.RemoteException.class,
                () -> sync.completeNewExchange(originRecord(), SaeFixtures.uplink()));

        assertTrue(originMap.get(HASH_1, HASH_2).isEmpty(), "origin reservation must be rolled back");
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty(), "peer reservation must be rolled back");
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.peer()));
    }


    private void reserveOrigin() {
        assertEquals(AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE));
    }

    private static ClientRecord originRecord() {
        return SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of());
    }
}