package fel.cvut.integration.node;

import fel.cvut.node.*;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.Qkd014Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Tag("integration")
@Timeout(60)
class KeystreamOnceTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap originMap;
    private AtomicRecordStateMap peerMap;
    private AtomicRecordStateMap otherMap;
    private NodeCommandsService peerService;
    private SharedKeyMaterialStore peerStore;
    private Qkd014Client qkd;
    private RmiManager rmi;

    @BeforeEach
    void setUp() throws Exception {
        originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
        otherMap = SaeFixtures.stateMap(OTHER_SAE, SQLITE.other());
        qkd = SaeFixtures.mockQkd();
        peerStore = SaeFixtures.keyStore(SQLITE.peer(), JceAesGcm.mockHsm());
        peerService = new NodeCommandsService(
                SaeFixtures.peerRef(),
                peerMap,
                qkd,
                peerStore
        );
        rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(peerService);
    }

    @Test
    void secondExchangeIsRefusedWhileShareIsAvailable() throws Exception {
        List<String> first = completeExchange(originMap, ORIGIN_SAE).orElseThrow();
        byte[] ciphertext = peerCiphertext();
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.NOT_INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        assertEquals(first, peerStore.readPayload(HASH_2, HASH_1).orElseThrow());
        assertArrayEquals(ciphertext, peerCiphertext());
        assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
    }

    @Test
    void peerReconcileDoesNotRegenerateWhileOriginAvailable() throws Exception {
        completeExchange(originMap, ORIGIN_SAE);
        byte[] ciphertext = peerCiphertext();
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.NOT_INSERTED,
                peerService.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability()
        );
        assertArrayEquals(ciphertext, peerCiphertext());
        assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
    }

    @Test
    void secondSaeCannotInsertOverAvailablePair() throws Exception {
        List<String> first = completeExchange(originMap, ORIGIN_SAE).orElseThrow();
        byte[] ciphertext = peerCiphertext();
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                otherMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), OTHER_SAE)
        );
        ProvisionSession.Exchange.Result second = new PeerRecordSync(SaeFixtures.otherRef(), otherMap, rmi, qkd)
                .completeNewExchange(SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of()), SaeFixtures.uplink());
        assertInstanceOf(ProvisionSession.Exchange.Result.SharedWithDifferentSae.class, second);
        assertEquals(
                ORIGIN_SAE,
                ((ProvisionSession.Exchange.Result.SharedWithDifferentSae) second).metadata().saeId());
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SYNCHRONIZATION,
                otherMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability());
        assertEquals(first, peerStore.readPayload(HASH_2, HASH_1).orElseThrow());
        assertArrayEquals(ciphertext, peerCiphertext());
        assertEquals(
                AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability()
        );
    }

    @Test
    void newExchangeAfterDeleteUsesNewCiphertext() throws Exception {
        completeExchange(originMap, ORIGIN_SAE);
        byte[] firstCiphertext = peerCiphertext();
        originMap.forceDelete(HASH_1, HASH_2);
        peerMap.forceDelete(HASH_2, HASH_1);
        List<String> second = completeExchange(originMap, ORIGIN_SAE).orElseThrow();
        byte[] secondCiphertext = peerCiphertext();
        assertFalse(Arrays.equals(firstCiphertext, secondCiphertext));
        assertEquals(second, peerStore.readPayload(HASH_2, HASH_1).orElseThrow());
        assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
    }

    private Optional<List<String>> completeExchange(AtomicRecordStateMap origin, String issuer)
            throws Exception {
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                origin.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), issuer)
        );
        return new PeerRecordSync(
                issuer.equals(ORIGIN_SAE) ? SaeFixtures.originRef() : SaeFixtures.otherRef(),
                origin,
                rmi,
                qkd
        ).completeNewExchange(SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of()), SaeFixtures.uplink()).keys();
    }

    private static byte[] peerCiphertext() throws Exception {
        try (Connection connection = SQLITE.peer().getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT ciphertext FROM shared_key_material WHERE client_hash1 = ? AND client_hash2 = ?")) {
            statement.setString(1, HASH_2);
            statement.setString(2, HASH_1);
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                return resultSet.getBytes(1);
            }
        }
    }
}
