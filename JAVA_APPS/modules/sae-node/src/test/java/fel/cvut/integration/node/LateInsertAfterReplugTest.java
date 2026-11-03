package fel.cvut.integration.node;

import fel.cvut.harness.AsCaller;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.AtomicRecordStateMap.RecordAvailability;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.KeyItem;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A peer insert of an ended attempt (its origin gave up on the RMI call, the device was
 * replugged and the same issuer locked the pair again with a new token) still runs on the peer.
 * Every write carries the lease token, so the late insert, and the late rollback delete of the
 * old attempt, are refused and never touch the newer share.
 */
@Tag("integration")
@Timeout(60)
class LateInsertAfterReplugTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private static final List<String> OLD_IDS = List.of("old-id");
    private static final List<String> NEW_IDS = List.of("new-id");

    private final CountDownLatch oldFetchStarted = new CountDownLatch(1);
    private final CountDownLatch releaseOldFetch = new CountDownLatch(1);
    private final ExecutorService rmiThread = Executors.newSingleThreadExecutor();

    private AtomicRecordStateMap peerMap;
    private SharedKeyMaterialStore peerStore;
    private Qkd014Client qkd;
    private NodeCommands peerAsOrigin;
    private String oldMaterial;
    private String newMaterial;
    private final String oldToken = PairLockRegistry.newToken();
    private final String newToken = PairLockRegistry.newToken();

    @BeforeEach
    void setUp() throws Exception {
        peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
        peerStore = SaeFixtures.keyStore(SQLITE.peer(), JceAesGcm.mockHsm());
        qkd = mock(Qkd014Client.class);
        oldMaterial = material((byte) 1);
        newMaterial = material((byte) 2);
        when(qkd.getKeyWithKeyIds(eq(ORIGIN_SAE), eq(NEW_IDS))).thenReturn(keys("new-id", newMaterial));
        NodeCommandsService service = new NodeCommandsService(SaeFixtures.peerRef(), peerMap, qkd, peerStore);
        peerAsOrigin = AsCaller.bind(ORIGIN_SAE, service);
    }

    @AfterEach
    void tearDown() {
        releaseOldFetch.countDown();
        rmiThread.shutdownNow();
    }

    @Test
    void lateOldInsertBeforeTheNewInsertIsRefusedAndWritesNothing() throws Exception {
        blockOldFetch(() -> keys("old-id", oldMaterial));
        Future<Void> oldInsert = startOldInsertAndReplug();

        releaseOldFetch.countDown();
        assertLostLease(oldInsert);
        assertTrue(peerMap.get(HASH_2, HASH_1).isEmpty(), "the late insert wrote nothing");
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.peer()));

        peerAsOrigin.insert(SaeFixtures.record(HASH_2, HASH_1, ORIGIN_SAE, NEW_IDS), newToken);
        assertNewShare();
    }

    @Test
    void lateOldInsertAfterTheNewInsertIsRefusedAndKeepsTheNewShare() throws Exception {
        blockOldFetch(() -> keys("old-id", oldMaterial));
        Future<Void> oldInsert = startOldInsertAndReplug();

        peerAsOrigin.insert(SaeFixtures.record(HASH_2, HASH_1, ORIGIN_SAE, NEW_IDS), newToken);
        releaseOldFetch.countDown();
        assertLostLease(oldInsert);
        assertNewShare();
    }

    @Test
    void lateRollbackDeleteOfTheOldAttemptDoesNotDeleteTheNewShare() throws Exception {
        blockOldFetch(() -> {
            throw new Qkd014ClientException("key ID not found", 400, null);
        });
        Future<Void> oldInsert = startOldInsertAndReplug();

        peerAsOrigin.insert(SaeFixtures.record(HASH_2, HASH_1, ORIGIN_SAE, NEW_IDS), newToken);
        releaseOldFetch.countDown();
        assertThrows(ExecutionException.class, () -> oldInsert.get(10, TimeUnit.SECONDS));

        // The old attempt's origin removes "its" peer row by its token: refused.
        assertThrows(PairLockLostException.class,
                () -> peerAsOrigin.deleteRecord(HASH_2, HASH_1, oldToken, oldToken));
        // Even under the live lease the old row token does not match the newer share.
        assertEquals(AtomicRecordStateMap.DeleteOutcome.TOKEN_MISMATCH,
                peerAsOrigin.deleteRecord(HASH_2, HASH_1, newToken, oldToken));
        assertNewShare();
    }

    /** Old attempt: lock the pair, start its insert, then replug and lock again with a new token. */
    private Future<Void> startOldInsertAndReplug() throws Exception {
        assertTrue(peerAsOrigin.lockPair(HASH_2, HASH_1, oldToken));
        Future<Void> oldInsert = rmiThread.submit(() -> {
            peerAsOrigin.insert(SaeFixtures.record(HASH_2, HASH_1, ORIGIN_SAE, OLD_IDS), oldToken);
            return null;
        });
        assertTrue(oldFetchStarted.await(10, TimeUnit.SECONDS));

        assertTrue(peerAsOrigin.lockPair(HASH_2, HASH_1, newToken), "the issuer replaces its own lease");
        assertFalse(oldInsert.isDone());
        return oldInsert;
    }

    private static void assertLostLease(Future<Void> late) {
        ExecutionException ex = assertThrows(ExecutionException.class, () -> late.get(10, TimeUnit.SECONDS));
        assertInstanceOf(PairLockLostException.class, ex.getCause());
    }

    private void assertNewShare() throws Exception {
        AtomicRecordStateMap.RecordMetadata row = peerMap.get(HASH_2, HASH_1).orElseThrow();
        assertEquals(RecordAvailability.KEYS_AVAILABLE, row.recordAvailability());
        assertEquals(newToken, row.token());
        assertEquals(List.of(newMaterial), peerStore.readPayload(HASH_2, HASH_1).orElseThrow());
    }

    private void blockOldFetch(ThrowingSupplier answer) throws Exception {
        when(qkd.getKeyWithKeyIds(eq(ORIGIN_SAE), eq(OLD_IDS))).thenAnswer(invocation -> {
            oldFetchStarted.countDown();
            assertTrue(releaseOldFetch.await(20, TimeUnit.SECONDS));
            return answer.get();
        });
    }

    @FunctionalInterface
    private interface ThrowingSupplier {
        KeyContainer get() throws Exception;
    }

    private static String material(byte fill) {
        byte[] bytes = new byte[64];
        Arrays.fill(bytes, fill);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static KeyContainer keys(String keyId, String material) {
        KeyItem item = new KeyItem();
        item.key_ID = keyId;
        item.key = material;
        KeyContainer container = new KeyContainer();
        container.keys = List.of(item);
        return container;
    }
}
