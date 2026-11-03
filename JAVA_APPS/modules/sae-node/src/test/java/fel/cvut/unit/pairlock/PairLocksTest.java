package fel.cvut.unit.pairlock;

import fel.cvut.harness.AsCaller;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.pairlock.PairBusyException;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.pairlock.PairLocks;
import fel.cvut.node.pairlock.PairOperation;
import fel.cvut.qkd.Qkd014Client;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.rmi.RemoteException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.OTHER_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pair locks across SAEs: fixed order (lower SAE ID first), refusal without waiting, renewal,
 * gap guard and release by token. Each SAE has its own registry behind a real
 * {@link NodeCommandsService}; calls carry the calling SAE as the authenticated caller.
 */
@Timeout(60)
@Tag("unit")
class PairLocksTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private final PairKey pair = PairKey.of(HASH_1, HASH_2);
    private final Map<String, NodeCommandsService> services = new ConcurrentHashMap<>();
    private final Map<String, PairLockRegistry> registries = new ConcurrentHashMap<>();
    private final Set<String> unreachable = ConcurrentHashMap.newKeySet();
    private final List<String> calls = java.util.Collections.synchronizedList(new ArrayList<>());
    private ScheduledExecutorService scheduler;

    @BeforeEach
    void setUp() {
        Qkd014Client qkd = SaeFixtures.mockQkd();
        services.put(ORIGIN_SAE, SaeFixtures.commands(SaeFixtures.originRef(), SQLITE.origin(), qkd, JceAesGcm.mockHsm()));
        services.put(PEER_SAE, SaeFixtures.commands(SaeFixtures.peerRef(), SQLITE.peer(), qkd, JceAesGcm.mockHsm()));
        services.put(OTHER_SAE, SaeFixtures.commands(SaeFixtures.otherRef(), SQLITE.other(), qkd, JceAesGcm.mockHsm()));
        registries.put(ORIGIN_SAE, SaeFixtures.registry(SQLITE.origin()));
        registries.put(PEER_SAE, SaeFixtures.registry(SQLITE.peer()));
        registries.put(OTHER_SAE, SaeFixtures.registry(SQLITE.other()));
        scheduler = Executors.newSingleThreadScheduledExecutor();
    }

    @AfterEach
    void tearDown() {
        scheduler.shutdownNow();
    }

    private PairLocks locksOf(String self, Duration renewInterval) {
        PairLocks.Remote remote = saeId -> {
            if (unreachable.contains(saeId)) {
                throw new RemoteException("SAE " + saeId + " unreachable (test)");
            }
            NodeCommands target = AsCaller.bind(self, services.get(saeId));
            return recording(saeId, target);
        };
        return new PairLocks(self, registries.get(self), remote, scheduler, renewInterval);
    }

    private PairLocks locksOf(String self) {
        return locksOf(self, Duration.ofHours(1));
    }

    private NodeCommands recording(String saeId, NodeCommands target) {
        return (NodeCommands) java.lang.reflect.Proxy.newProxyInstance(
                NodeCommands.class.getClassLoader(), new Class<?>[]{NodeCommands.class},
                (proxy, method, args) -> {
                    calls.add(method.getName() + "@" + saeId);
                    try {
                        return method.invoke(target, args);
                    } catch (java.lang.reflect.InvocationTargetException ex) {
                        throw ex.getCause();
                    }
                });
    }

    private boolean free(String saeId) {
        return registries.get(saeId).lease(pair).isEmpty();
    }

    @Test
    void acquireLocksBothWithOneTokenIssuedByTheCaller() throws Exception {
        try (PairOperation operation = locksOf(PEER_SAE).acquire(PEER_SAE, ORIGIN_SAE, HASH_2, HASH_1)) {
            assertEquals(ORIGIN_SAE, operation.firstSaeId(), "lower SAE ID first");
            assertEquals(PEER_SAE, operation.secondSaeId());
            for (String sae : List.of(ORIGIN_SAE, PEER_SAE)) {
                PairLockRegistry.Lease lease = registries.get(sae).lease(pair).orElseThrow();
                assertEquals(operation.token(), lease.token());
                assertEquals(PEER_SAE, lease.issuerSaeId());
            }
            assertEquals(List.of("lockPair@" + ORIGIN_SAE), calls);
        }
        assertTrue(free(ORIGIN_SAE));
        assertTrue(free(PEER_SAE));
    }

    @Test
    void numericSaeIdsAreOrderedNumerically() {
        assertTrue(PairLocks.SAE_ORDER.compare("9", "10") < 0);
        assertTrue(PairLocks.SAE_ORDER.compare("sae-1", "sae-2") < 0);
    }

    @Test
    void refusedFirstLockNeverTouchesTheSecondSae() throws Exception {
        assertTrue(registries.get(ORIGIN_SAE).tryAcquire(pair, OTHER_SAE, PairLockRegistry.newToken()));

        PairBusyException busy = assertThrows(PairBusyException.class,
                () -> locksOf(PEER_SAE).acquire(PEER_SAE, ORIGIN_SAE, HASH_2, HASH_1));

        assertEquals(PairBusyException.BUSY_MESSAGE, busy.getMessage());
        assertTrue(free(PEER_SAE), "the higher SAE must not be locked when the lower refused");
    }

    @Test
    void refusedSecondLockReleasesTheFirst() throws Exception {
        String foreign = PairLockRegistry.newToken();
        assertTrue(registries.get(PEER_SAE).tryAcquire(pair, OTHER_SAE, foreign));

        assertThrows(PairBusyException.class, () -> locksOf(ORIGIN_SAE).acquire(ORIGIN_SAE, PEER_SAE, HASH_1, HASH_2));

        assertTrue(free(ORIGIN_SAE), "the first lock is released by token");
        assertTrue(registries.get(PEER_SAE).holds(pair, foreign), "the other operation keeps its lock");
    }

    @Test
    void unreachableSecondSaeReleasesTheFirstAndFails() {
        unreachable.add(PEER_SAE);
        assertThrows(RemoteException.class, () -> locksOf(ORIGIN_SAE).acquire(ORIGIN_SAE, PEER_SAE, HASH_1, HASH_2));
        assertTrue(free(ORIGIN_SAE));
    }

    @Test
    void bothOriginsAtOnceNeverDeadlockAndExactlyOneWins() throws Exception {
        PairLocks origin = locksOf(ORIGIN_SAE);
        PairLocks peer = locksOf(PEER_SAE);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < 40; round++) {
                CyclicBarrier barrier = new CyclicBarrier(2);
                CountDownLatch bothDone = new CountDownLatch(2);
                Future<PairOperation> a = executor.submit(() -> attempt(barrier, bothDone,
                        () -> origin.acquire(ORIGIN_SAE, PEER_SAE, HASH_1, HASH_2)));
                Future<PairOperation> b = executor.submit(() -> attempt(barrier, bothDone,
                        () -> peer.acquire(PEER_SAE, ORIGIN_SAE, HASH_2, HASH_1)));
                PairOperation first = a.get(10, TimeUnit.SECONDS);
                PairOperation second = b.get(10, TimeUnit.SECONDS);
                assertTrue((first == null) != (second == null), "exactly one of the two origins wins, round " + round);
                PairOperation winner = first != null ? first : second;
                for (String sae : List.of(ORIGIN_SAE, PEER_SAE)) {
                    assertTrue(registries.get(sae).holds(pair, winner.token()));
                }
                winner.close();
                assertTrue(free(ORIGIN_SAE));
                assertTrue(free(PEER_SAE));
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private interface Acquire {
        PairOperation run() throws Exception;
    }

    private static PairOperation attempt(CyclicBarrier barrier, CountDownLatch bothDone, Acquire acquire)
            throws Exception {
        barrier.await(5, TimeUnit.SECONDS);
        try {
            return acquire.run();
        } catch (PairBusyException busy) {
            return null;
        } finally {
            bothDone.countDown();
            // Hold the outcome until both attempts finished, so the winner cannot release early.
            bothDone.await(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void releaseIsByTokenOnly() throws Exception {
        PairOperation operation = locksOf(ORIGIN_SAE).acquire(ORIGIN_SAE, PEER_SAE, HASH_1, HASH_2);
        assertFalse(AsCaller.call(ORIGIN_SAE,
                () -> services.get(PEER_SAE).releasePair(HASH_2, HASH_1, PairLockRegistry.newToken())));
        assertFalse(AsCaller.call(OTHER_SAE,
                () -> services.get(PEER_SAE).lockPair(HASH_2, HASH_1, PairLockRegistry.newToken())));
        assertTrue(registries.get(PEER_SAE).holds(pair, operation.token()));
        operation.close();
        operation.close();
        assertTrue(free(ORIGIN_SAE));
        assertTrue(free(PEER_SAE));
    }

    @Test
    void closeReleasesTheRemoteSaeBeforeThisOne() throws Exception {
        PairOperation operation = locksOf(PEER_SAE).acquire(PEER_SAE, ORIGIN_SAE, HASH_2, HASH_1);
        calls.clear();
        PairLockRegistry local = registries.get(PEER_SAE);
        services.put(ORIGIN_SAE, wrapRelease(services.get(ORIGIN_SAE),
                () -> assertTrue(local.holds(pair, operation.token()), "local lock still held while remote releases")));
        operation.close();
        assertEquals(List.of("releasePair@" + ORIGIN_SAE), calls);
        assertTrue(free(PEER_SAE));
        assertTrue(free(ORIGIN_SAE));
    }

    private static NodeCommandsService wrapRelease(NodeCommandsService delegate, Runnable before) {
        return new NodeCommandsService(SaeFixtures.originRef(),
                SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin()), SaeFixtures.mockQkd(),
                SaeFixtures.keyStore(SQLITE.origin(), JceAesGcm.mockHsm())) {
            @Override
            public boolean releasePair(String h1, String h2, String token) throws RemoteException {
                before.run();
                return delegate.releasePair(h1, h2, token);
            }
        };
    }

    @Test
    void renewalKeepsBothLeasesAlive() throws Exception {
        try (PairOperation operation = locksOf(ORIGIN_SAE, Duration.ofMillis(20))
                .acquire(ORIGIN_SAE, PEER_SAE, HASH_1, HASH_2)) {
            long deadline = System.currentTimeMillis() + 5_000;
            while (calls.stream().noneMatch(c -> c.equals("renewPair@" + PEER_SAE))
                    && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(calls.contains("renewPair@" + PEER_SAE), "background renewal reaches the remote SAE");
            assertFalse(operation.isAborted());
        }
    }

    @Test
    void renewalFailureAbortsTheOperation() throws Exception {
        PairOperation operation = locksOf(ORIGIN_SAE, Duration.ofMillis(20))
                .acquire(ORIGIN_SAE, PEER_SAE, HASH_1, HASH_2);
        CountDownLatch aborted = new CountDownLatch(1);
        operation.onAbort(aborted::countDown);

        // The peer lost the lease (for example it restarted).
        assertTrue(registries.get(PEER_SAE).release(pair, operation.token()));

        assertTrue(aborted.await(5, TimeUnit.SECONDS), "a failed renewal aborts the operation");
        assertTrue(operation.isAborted());
        assertThrows(PairLockLostException.class, operation::checkpoint);
        operation.close();
        assertTrue(free(ORIGIN_SAE));
    }

    @Test
    void unreachablePeerDuringRenewalAbortsTheOperation() throws Exception {
        PairOperation operation = locksOf(ORIGIN_SAE, Duration.ofMillis(20))
                .acquire(ORIGIN_SAE, PEER_SAE, HASH_1, HASH_2);
        CountDownLatch aborted = new CountDownLatch(1);
        operation.onAbort(aborted::countDown);
        unreachable.add(PEER_SAE);
        assertTrue(aborted.await(5, TimeUnit.SECONDS));
        operation.close();
    }

    @Test
    void gapGuardRenewsBothOrAborts() throws Exception {
        PairOperation operation = locksOf(ORIGIN_SAE).acquire(ORIGIN_SAE, PEER_SAE, HASH_1, HASH_2);
        calls.clear();
        operation.checkpoint();
        assertEquals(List.of("renewPair@" + PEER_SAE), calls);
        assertFalse(operation.isAborted());

        // A same-issuer replacement on the peer (a later attempt) kills this token there.
        assertTrue(registries.get(PEER_SAE).tryAcquire(pair, ORIGIN_SAE, PairLockRegistry.newToken()));
        boolean[] hook = {false};
        operation.onAbort(() -> hook[0] = true);

        assertThrows(PairLockLostException.class, operation::checkpoint);
        assertTrue(operation.isAborted());
        assertTrue(hook[0]);
        operation.close();
    }

    @Test
    void anOperationNeedsTwoDifferentSaes() {
        assertThrows(IllegalArgumentException.class,
                () -> locksOf(ORIGIN_SAE).acquire(ORIGIN_SAE, ORIGIN_SAE, HASH_1, HASH_2));
    }
}
