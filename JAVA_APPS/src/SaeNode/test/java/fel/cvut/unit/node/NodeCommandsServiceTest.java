package fel.cvut.unit.node;

import fel.cvut.harness.AsCaller;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordAvailability;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordMetadata;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.rmi.AccessException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@Tag("unit")
class NodeCommandsServiceTest {

    private AtomicRecordStateMap stateMap;
    private SharedKeyMaterialStore store;
    private Qkd014Client qkd;
    private RmiManager rmi;
    private NodeCommandsService service;
    /** The service as called over pinned RMI by the origin SAE. */
    private NodeCommands asOrigin;

    @BeforeEach
    void setUp() {
        stateMap = mock(AtomicRecordStateMap.class);
        store = mock(SharedKeyMaterialStore.class);
        qkd = mock(Qkd014Client.class);
        rmi = mock(RmiManager.class);
        service = new NodeCommandsService(SaeFixtures.peerRef(), stateMap, qkd, store, rmi);
        asOrigin = AsCaller.bind(ORIGIN_SAE, service);
    }



    @Test
    void insertWithoutFetchReservationIsRefusedBeforeQkd() throws Exception {
        when(stateMap.get(HASH_1, HASH_2)).thenReturn(Optional.empty());
        RemoteException none = assertThrows(RemoteException.class, () -> asOrigin.insert(record(), ORIGIN_SAE));
        assertTrue(none.getMessage().contains("RECORD_FETCHING_STARTED"));

        when(stateMap.get(HASH_1, HASH_2))
                .thenReturn(Optional.of(metadata(RecordAvailability.RECORD_SYNCHRONIZATION, ORIGIN_SAE)));
        assertThrows(RemoteException.class, () -> asOrigin.insert(record(), ORIGIN_SAE));

        when(stateMap.get(HASH_1, HASH_2))
                .thenReturn(Optional.of(metadata(RecordAvailability.RECORD_FETCHING_STARTED, OTHER_SAE)));
        assertThrows(RemoteException.class, () -> asOrigin.insert(record(), ORIGIN_SAE));

        assertThrows(NullPointerException.class, () -> asOrigin.insert(null, ORIGIN_SAE));
        verifyNoInteractions(qkd, store);
        verify(stateMap, never()).tryDelete(anyString(), anyString(), anyString());
    }

    @Test
    void insertResolvesKeyIdsStoresMaterialAndFinalizes() throws Exception {
        fetching();
        KeyContainer keys = SaeFixtures.keyContainer("key-1", 32);
        when(qkd.getKeyWithKeyIds(ORIGIN_SAE, List.of("key-1"))).thenReturn(keys);
        when(stateMap.finishRecordInsert(HASH_1, HASH_2)).thenReturn(true);

        assertTrue(asOrigin.insert(record(), ORIGIN_SAE));

        ArgumentCaptor<ClientRecord> stored = ArgumentCaptor.forClass(ClientRecord.class);
        var order = inOrder(qkd, store, stateMap);
        order.verify(qkd).getKeyWithKeyIds(ORIGIN_SAE, List.of("key-1"));
        order.verify(store).write(stored.capture());
        order.verify(stateMap).finishRecordInsert(HASH_1, HASH_2);
        assertEquals(List.of(keys.keys.get(0).key), stored.getValue().getPayload(),
                "key IDs must be replaced by key material before storing");
        assertEquals(HASH_1, stored.getValue().getClientHash1());
        verify(stateMap, never()).tryDelete(anyString(), anyString(), anyString());
    }

    @Test
    void insertTreatsConcurrentPromotionAsSuccess() throws Exception {
        when(stateMap.get(HASH_1, HASH_2)).thenReturn(
                Optional.of(metadata(RecordAvailability.RECORD_FETCHING_STARTED, ORIGIN_SAE)),
                Optional.of(metadata(RecordAvailability.ORIGIN_PROVISIONED, ORIGIN_SAE)));
        when(qkd.getKeyWithKeyIds(anyString(), anyList())).thenReturn(SaeFixtures.keyContainer("key-1", 16));
        when(stateMap.finishRecordInsert(HASH_1, HASH_2)).thenReturn(false);

        assertTrue(asOrigin.insert(record(), ORIGIN_SAE));
        verify(stateMap, never()).tryDelete(anyString(), anyString(), anyString());
    }

    @Test
    void insertRollsBackWhenFinalizationFails() throws Exception {
        when(stateMap.get(HASH_1, HASH_2)).thenReturn(
                Optional.of(metadata(RecordAvailability.RECORD_FETCHING_STARTED, ORIGIN_SAE)),
                Optional.empty());
        when(qkd.getKeyWithKeyIds(anyString(), anyList())).thenReturn(SaeFixtures.keyContainer("key-1", 16));
        when(stateMap.finishRecordInsert(HASH_1, HASH_2)).thenReturn(false);

        RemoteException ex = assertThrows(RemoteException.class, () -> asOrigin.insert(record(), ORIGIN_SAE));

        /*
         * Current behaviour: the inner "finalization failed" RemoteException is thrown inside the
         * try block, caught by the generic catch(Exception) and rolled back a second time, so the
         * caller sees "Target record insert failed." with the finalization error as cause.
         */
        assertEquals("Target record insert failed.", ex.getMessage().split(";")[0]);
        assertInstanceOf(RemoteException.class, ex.getCause());
        assertTrue(ex.getCause().getMessage().startsWith("Target record finalization failed"));
        verify(stateMap, times(2)).tryDelete(HASH_1, HASH_2, ORIGIN_SAE);
    }

    @Test
    void insertRollsBackWhenQkdKeyLookupFails() throws Exception {
        fetching();
        Qkd014ClientException qkdError = new Qkd014ClientException("key ID not found", 400, null);
        when(qkd.getKeyWithKeyIds(anyString(), anyList())).thenThrow(qkdError);

        RemoteException ex = assertThrows(RemoteException.class, () -> asOrigin.insert(record(), ORIGIN_SAE));

        assertTrue(ex.getMessage().startsWith("Target record insert failed while resolving key IDs."));
        assertSame(qkdError, ex.getCause());
        verify(stateMap).tryDelete(HASH_1, HASH_2, ORIGIN_SAE);
        verifyNoInteractions(store);
        verify(stateMap, never()).finishRecordInsert(anyString(), anyString());
    }

    @Test
    void insertRollsBackWhenStoreWriteFails() throws Exception {
        fetching();
        when(qkd.getKeyWithKeyIds(anyString(), anyList())).thenReturn(SaeFixtures.keyContainer("key-1", 16));
        IOException ioError = new IOException("disk full");
        doThrow(ioError).when(store).write(any());

        RemoteException ex = assertThrows(RemoteException.class, () -> asOrigin.insert(record(), ORIGIN_SAE));

        assertTrue(ex.getMessage().startsWith("Target record insert failed."));
        assertSame(ioError, ex.getCause());
        verify(stateMap).tryDelete(HASH_1, HASH_2, ORIGIN_SAE);
        verify(stateMap, never()).finishRecordInsert(anyString(), anyString());
    }


    @Test
    void deleteShareWithoutLocalRowDoesNothing() throws Exception {
        when(stateMap.get(HASH_1, HASH_2)).thenReturn(Optional.empty());
        asOrigin.deleteShare(HASH_1, HASH_2);
        verify(stateMap, never()).forceDelete(anyString(), anyString());
        verifyNoInteractions(rmi);
    }

    @Test
    void deleteShareOwnedBySelfOnlyDeletesLocally() throws Exception {
        when(stateMap.get(HASH_1, HASH_2)).thenReturn(Optional.of(
                new RecordMetadata(Instant.now(), RecordAvailability.RECORD_SHARED, PEER_SAE, ORIGIN_SAE, 1)));
        asOrigin.deleteShare(HASH_1, HASH_2);
        verify(stateMap).forceDelete(HASH_1, HASH_2);
        verifyNoInteractions(rmi);
    }

    @Test
    void deleteShareRemovesRemoteCounterpartWithSwappedHashesFirst() throws Exception {
        when(stateMap.get(HASH_1, HASH_2)).thenReturn(Optional.of(
                new RecordMetadata(Instant.now(), RecordAvailability.RECORD_SHARED, ORIGIN_SAE, ORIGIN_SAE, 1)));
        NodeCommands remote = mock(NodeCommands.class);
        when(rmi.connectBySaeId(ORIGIN_SAE)).thenReturn(remote);

        asOrigin.deleteShare(HASH_1, HASH_2);

        var order = inOrder(remote, stateMap);
        order.verify(remote).removeRecord(HASH_2, HASH_1);
        order.verify(stateMap).forceDelete(HASH_1, HASH_2);
    }

    @Test
    void deleteShareKeepsLocalRowWhenRemoteFails() throws Exception {
        when(stateMap.get(HASH_1, HASH_2)).thenReturn(Optional.of(
                new RecordMetadata(Instant.now(), RecordAvailability.RECORD_SHARED, ORIGIN_SAE, ORIGIN_SAE, 1)));
        when(rmi.connectBySaeId(ORIGIN_SAE)).thenThrow(new NotBoundException("down"));

        assertThrows(NotBoundException.class, () -> asOrigin.deleteShare(HASH_1, HASH_2));
        verify(stateMap, never()).forceDelete(anyString(), anyString());
    }

    @Test
    void callsWithoutAuthenticatedCallerAreRefused() {
        when(stateMap.get(HASH_1, HASH_2)).thenReturn(Optional.of(metadata(RecordAvailability.RECORD_SHARED, ORIGIN_SAE)));
        assertThrows(AccessException.class, () -> service.getRecordMetadata(HASH_1, HASH_2));
        assertThrows(AccessException.class,
                () -> service.synchronize(SaeFixtures.header(HASH_1, HASH_2, ORIGIN_SAE), ORIGIN_SAE));
        assertThrows(AccessException.class, () -> service.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
        assertThrows(AccessException.class, () -> service.insert(record(), ORIGIN_SAE));
        assertThrows(AccessException.class, () -> service.removeRecord(HASH_1, HASH_2));
        assertThrows(AccessException.class, () -> service.markOriginProvisioned(HASH_1, HASH_2));
        assertThrows(AccessException.class, () -> service.deleteShare(HASH_1, HASH_2));
        verify(stateMap, never()).forceDelete(anyString(), anyString());
        verify(stateMap, never()).markOriginProvisioned(anyString(), anyString());
        verifyNoInteractions(qkd, store, rmi);
    }

    @Test
    void callerMustMatchClaimedIssuingSae() {
        NodeCommands asOther = AsCaller.bind(OTHER_SAE, service);
        fetching();
        assertThrows(AccessException.class,
                () -> asOther.synchronize(SaeFixtures.header(HASH_1, HASH_2, ORIGIN_SAE), ORIGIN_SAE));
        assertThrows(AccessException.class,
                () -> asOther.synchronize(SaeFixtures.header(HASH_1, HASH_2, ORIGIN_SAE), OTHER_SAE),
                "header saeId must also be the caller");
        assertThrows(AccessException.class, () -> asOther.lockFetch(HASH_1, HASH_2, ORIGIN_SAE));
        assertThrows(AccessException.class, () -> asOther.insert(record(), ORIGIN_SAE));
        verify(stateMap, never()).synchronize(any(), anyString());
        verify(stateMap, never()).lockFetch(anyString(), anyString(), anyString());
        verifyNoInteractions(qkd, store);
    }

    @Test
    void nonPartyCannotRemoveOrMarkRecord() throws Exception {
        NodeCommands asOther = AsCaller.bind(OTHER_SAE, service);
        when(stateMap.get(HASH_1, HASH_2)).thenReturn(Optional.of(
                new RecordMetadata(Instant.now(), RecordAvailability.RECORD_SHARED, ORIGIN_SAE, ORIGIN_SAE, 1)));
        assertThrows(AccessException.class, () -> asOther.removeRecord(HASH_1, HASH_2));
        assertThrows(AccessException.class, () -> asOther.markOriginProvisioned(HASH_1, HASH_2));
        verify(stateMap, never()).forceDelete(anyString(), anyString());
        verify(stateMap, never()).markOriginProvisioned(anyString(), anyString());

        when(stateMap.get(HASH_1, HASH_2)).thenReturn(Optional.empty());
        assertNull(asOther.removeRecord(HASH_1, HASH_2), "absent row: nothing to authorize, nothing deleted");
        assertEquals(false, asOther.markOriginProvisioned(HASH_1, HASH_2));
    }

    @Test
    void nonPartyDeleteShareOnlyForCompletedShare() throws Exception {
        NodeCommands asOther = AsCaller.bind(OTHER_SAE, service);
        when(stateMap.get(HASH_1, HASH_2)).thenReturn(Optional.of(
                new RecordMetadata(Instant.now(), RecordAvailability.RECORD_FETCHING_STARTED, ORIGIN_SAE, ORIGIN_SAE, 1)));
        assertThrows(AccessException.class, () -> asOther.deleteShare(HASH_1, HASH_2));
        verify(stateMap, never()).forceDelete(anyString(), anyString());
        verifyNoInteractions(rmi);

        when(stateMap.get(HASH_1, HASH_2)).thenReturn(Optional.of(
                new RecordMetadata(Instant.now(), RecordAvailability.ORIGIN_PROVISIONED, ORIGIN_SAE, ORIGIN_SAE, 1)));
        NodeCommands remote = mock(NodeCommands.class);
        when(rmi.connectBySaeId(ORIGIN_SAE)).thenReturn(remote);
        asOther.deleteShare(HASH_1, HASH_2);
        var order = inOrder(remote, stateMap);
        order.verify(remote).removeRecord(HASH_2, HASH_1);
        order.verify(stateMap).forceDelete(HASH_1, HASH_2);
    }

    private void fetching() {
        when(stateMap.get(HASH_1, HASH_2))
                .thenReturn(Optional.of(metadata(RecordAvailability.RECORD_FETCHING_STARTED, ORIGIN_SAE)));
    }

    private static RecordMetadata metadata(RecordAvailability availability, String issuer) {
        return new RecordMetadata(Instant.now(), availability, PEER_SAE, issuer, SaeFixtures.padPlain());
    }

    private static ClientRecord record() {
        return SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of("key-1"));
    }
}