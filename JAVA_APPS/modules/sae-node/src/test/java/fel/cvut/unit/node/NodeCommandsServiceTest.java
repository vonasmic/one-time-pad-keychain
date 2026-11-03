package fel.cvut.unit.node;

import fel.cvut.harness.AsCaller;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.AtomicRecordStateMap.DeleteOutcome;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.AccessException;
import java.rmi.RemoteException;
import java.util.List;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The peer side of the RMI contract on a real SQLite DB: the caller comes from the (simulated)
 * pinned TLS binding, leases are taken in its name, and writes run only under its live lease.
 * The peer stores the pair as (HASH_2, HASH_1).
 */
@Timeout(60)
@Tag("unit")
class NodeCommandsServiceTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private AtomicRecordStateMap stateMap;
    private SharedKeyMaterialStore store;
    private PairLockRegistry registry;
    private Qkd014Client qkd;
    private NodeCommandsService service;
    /** The service as called over pinned RMI by the origin SAE. */
    private NodeCommands asOrigin;
    private NodeCommands asOther;
    private final PairKey pair = PairKey.of(HASH_1, HASH_2);

    @BeforeEach
    void setUp() {
        stateMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
        store = SaeFixtures.keyStore(SQLITE.peer(), JceAesGcm.mockHsm());
        registry = stateMap.registry();
        qkd = SaeFixtures.mockQkd();
        service = new NodeCommandsService(SaeFixtures.peerRef(), stateMap, qkd, store);
        asOrigin = AsCaller.bind(ORIGIN_SAE, service);
        asOther = AsCaller.bind(OTHER_SAE, service);
    }

    @Test
    void callsWithoutAuthenticatedCallerAreRefused() {
        String token = PairLockRegistry.newToken();
        assertThrows(AccessException.class, () -> service.getRecordMetadata(HASH_2, HASH_1));
        assertThrows(AccessException.class, () -> service.lockPair(HASH_2, HASH_1, token));
        assertThrows(AccessException.class, () -> service.renewPair(HASH_2, HASH_1, token));
        assertThrows(AccessException.class, () -> service.releasePair(HASH_2, HASH_1, token));
        assertThrows(AccessException.class, () -> service.insert(record(), token));
        assertThrows(AccessException.class, () -> service.deleteRecord(HASH_2, HASH_1, token, token));
        assertTrue(registry.lease(pair).isEmpty());
    }

    @Test
    void lockPairIsTakenInTheCallersNameAndRefusedToAnotherCaller() throws Exception {
        String token = PairLockRegistry.newToken();
        assertTrue(asOrigin.lockPair(HASH_2, HASH_1, token));
        assertEquals(ORIGIN_SAE, registry.lease(pair).orElseThrow().issuerSaeId());
        assertFalse(asOther.lockPair(HASH_2, HASH_1, PairLockRegistry.newToken()));

        String replacement = PairLockRegistry.newToken();
        assertTrue(asOrigin.lockPair(HASH_1, HASH_2, replacement), "same caller replaces its lease");
        assertFalse(asOrigin.renewPair(HASH_2, HASH_1, token));
        assertTrue(asOrigin.renewPair(HASH_2, HASH_1, replacement));
        assertFalse(asOther.releasePair(HASH_2, HASH_1, token));
        assertTrue(asOrigin.releasePair(HASH_2, HASH_1, replacement));
        assertTrue(registry.lease(pair).isEmpty());
    }

    @Test
    void anotherSaeCannotRenewOrReleaseTheLeaseEvenWithItsToken() throws Exception {
        // row tokens are readable by any SAE through getRecordMetadata, so the token alone is no proof
        String token = PairLockRegistry.newToken();
        assertTrue(asOrigin.lockPair(HASH_2, HASH_1, token));
        assertFalse(asOther.renewPair(HASH_2, HASH_1, token));
        assertFalse(asOther.releasePair(HASH_2, HASH_1, token));
        assertEquals(token, registry.lease(pair).orElseThrow().token());
        assertEquals(ORIGIN_SAE, registry.lease(pair).orElseThrow().issuerSaeId());
        assertTrue(asOrigin.renewPair(HASH_2, HASH_1, token));
        assertTrue(asOrigin.releasePair(HASH_2, HASH_1, token));
    }

    @Test
    void insertWithoutTheCallersLeaseIsRefusedBeforeQkd() throws Exception {
        Qkd014Client strictQkd = mock(Qkd014Client.class);
        NodeCommands origin = AsCaller.bind(ORIGIN_SAE,
                new NodeCommandsService(SaeFixtures.peerRef(), stateMap, strictQkd, store));
        String token = PairLockRegistry.newToken();

        assertThrows(PairLockLostException.class, () -> origin.insert(record(), token));

        assertTrue(asOther.lockPair(HASH_2, HASH_1, token));
        assertThrows(PairLockLostException.class, () -> origin.insert(record(), token),
                "a lease of another SAE does not authorize the caller, even with the same token");

        verifyNoInteractions(strictQkd);
        assertEquals(0, SaeFixtures.countRecords(SQLITE.peer()));
    }

    @Test
    void insertHeaderMustNameTheCaller() throws Exception {
        String token = PairLockRegistry.newToken();
        assertTrue(asOther.lockPair(HASH_2, HASH_1, token));
        AccessException denied = assertThrows(AccessException.class, () -> asOther.insert(record(), token));
        assertTrue(denied.getMessage().contains(OTHER_SAE));
        assertEquals(0, SaeFixtures.countRecords(SQLITE.peer()));
    }

    @Test
    void insertResolvesKeyIdsAndStoresTheRowWithTheToken() throws Exception {
        KeyContainer keys = SaeFixtures.keyContainer("key-1", 32);
        when(qkd.getKeyWithKeyIds(ORIGIN_SAE, List.of("key-1"))).thenReturn(keys);
        String token = PairLockRegistry.newToken();
        assertTrue(asOrigin.lockPair(HASH_2, HASH_1, token));

        asOrigin.insert(record(), token);

        AtomicRecordStateMap.RecordMetadata row = asOrigin.getRecordMetadata(HASH_2, HASH_1);
        assertEquals(token, row.token());
        assertEquals(ORIGIN_SAE, row.saeId());
        assertEquals(ORIGIN_SAE, row.issuingSaeId());
        assertEquals(AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE, row.recordAvailability());
        assertEquals(List.of(keys.keys.get(0).key), store.readPayload(HASH_2, HASH_1).orElseThrow(),
                "key IDs are replaced by key material before storing");
        assertNull(asOrigin.getRecordMetadata(HASH_1, HASH_2), "orientation is exact");
    }

    @Test
    void qkdFailureLeavesNothingStored() throws Exception {
        when(qkd.getKeyWithKeyIds(anyString(), anyList()))
                .thenThrow(new Qkd014ClientException("key ID not found", 400, null));
        String token = PairLockRegistry.newToken();
        assertTrue(asOrigin.lockPair(HASH_2, HASH_1, token));

        assertThrows(RemoteException.class, () -> asOrigin.insert(record(), token));

        assertEquals(0, SaeFixtures.countRecords(SQLITE.peer()));
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.peer()));
    }

    @Test
    void lateInsertAndDeleteOfAnOldAttemptAreRefusedByToken() throws Exception {
        String oldToken = PairLockRegistry.newToken();
        assertTrue(asOrigin.lockPair(HASH_2, HASH_1, oldToken));
        // The device was replugged: the same origin starts again and replaces its lease.
        String newToken = PairLockRegistry.newToken();
        assertTrue(asOrigin.lockPair(HASH_2, HASH_1, newToken));
        asOrigin.insert(record(), newToken);

        assertThrows(PairLockLostException.class, () -> asOrigin.insert(record(), oldToken));
        assertThrows(PairLockLostException.class,
                () -> asOrigin.deleteRecord(HASH_2, HASH_1, oldToken, newToken));
        assertEquals(DeleteOutcome.TOKEN_MISMATCH, asOrigin.deleteRecord(HASH_2, HASH_1, newToken, oldToken),
                "a rollback of the old attempt does not delete the new row");

        assertEquals(newToken, SaeFixtures.rowToken(SQLITE.peer(), HASH_2, HASH_1));
        assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
    }

    @Test
    void deleteRecordIsACompareAndDeleteUnderTheCallersLease() throws Exception {
        String rowToken = PairLockRegistry.newToken();
        assertTrue(asOrigin.lockPair(HASH_2, HASH_1, rowToken));
        asOrigin.insert(record(), rowToken);
        assertTrue(asOrigin.releasePair(HASH_2, HASH_1, rowToken));

        String lease = PairLockRegistry.newToken();
        assertThrows(PairLockLostException.class, () -> asOther.deleteRecord(HASH_2, HASH_1, lease, rowToken),
                "no lease, no delete");
        assertTrue(asOther.lockPair(HASH_2, HASH_1, lease));
        assertThrows(PairLockLostException.class, () -> asOrigin.deleteRecord(HASH_2, HASH_1, lease, rowToken),
                "the lease must belong to the caller");

        assertEquals(DeleteOutcome.TOKEN_MISMATCH,
                asOther.deleteRecord(HASH_2, HASH_1, lease, PairLockRegistry.newToken()));
        assertEquals(1, SaeFixtures.countRecords(SQLITE.peer()));
        assertEquals(DeleteOutcome.DELETED, asOther.deleteRecord(HASH_2, HASH_1, lease, rowToken));
        assertEquals(DeleteOutcome.ABSENT, asOther.deleteRecord(HASH_2, HASH_1, lease, rowToken));
        assertEquals(0, SaeFixtures.countRecords(SQLITE.peer()));
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.peer()), "key material is deleted with the row");
    }

    private static ClientRecord record() {
        return SaeFixtures.record(HASH_2, HASH_1, ORIGIN_SAE, List.of("key-1"));
    }
}
