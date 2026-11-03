package fel.cvut.unit.pairlock;

import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(60)
@Tag("unit")
class PairLockRegistryTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private static final Duration LEASE = PairLockRegistry.LEASE_DURATION;
    private final AtomicLong clock = new AtomicLong(1_000);
    private final PairKey pair = PairKey.of(HASH_1, HASH_2);
    private PairLockRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new PairLockRegistry(SQLITE.origin(), LEASE, clock::get);
    }

    @Test
    void pairKeyIgnoresOrientation() {
        assertEquals(PairKey.of(HASH_1, HASH_2), PairKey.of(HASH_2, HASH_1));
    }

    @Test
    void tokensAre128BitAndFresh() {
        String token = PairLockRegistry.newToken();
        assertEquals(32, token.length());
        assertNotEquals(token, PairLockRegistry.newToken());
    }

    @Test
    void freePairIsAcquired() {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        assertTrue(registry.holds(pair, token));
        assertEquals(ORIGIN_SAE, registry.lease(pair).orElseThrow().issuerSaeId());
    }

    @Test
    void anotherIssuerIsRefusedWhileTheLeaseIsLive() {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        clock.addAndGet(LEASE.toNanos() - 1);
        assertFalse(registry.tryAcquire(pair, PEER_SAE, PairLockRegistry.newToken()));
        assertTrue(registry.holds(pair, token));
    }

    @Test
    void sameIssuerReplacesItsLeaseAndTheOldTokenIsDead() {
        String old = PairLockRegistry.newToken();
        String fresh = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, old));
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, fresh));
        assertFalse(registry.holds(pair, old));
        assertTrue(registry.holds(pair, fresh));
        assertFalse(registry.renew(pair, old));
        assertFalse(registry.release(pair, old));
        assertTrue(registry.holds(pair, fresh));
    }

    @Test
    void expiredLeaseIsTakenByAnyIssuer() {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        clock.addAndGet(LEASE.toNanos());
        assertFalse(registry.holds(pair, token));
        assertTrue(registry.lease(pair).isEmpty());
        assertFalse(registry.renew(pair, token), "an expired lease cannot be renewed");
        String other = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, PEER_SAE, other));
        assertTrue(registry.holds(pair, other));
    }

    @Test
    void renewExtendsTheLeaseOnlyForTheHolder() {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        clock.addAndGet(LEASE.toNanos() - 10);
        assertFalse(registry.renew(pair, PairLockRegistry.newToken()));
        assertTrue(registry.renew(pair, token));
        clock.addAndGet(LEASE.toNanos() - 10);
        assertTrue(registry.holds(pair, token), "renewal restarted the five minutes");
        assertFalse(registry.tryAcquire(pair, PEER_SAE, PairLockRegistry.newToken()));
    }

    @Test
    void releaseNeedsTheToken() {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        assertFalse(registry.release(pair, PairLockRegistry.newToken()));
        assertTrue(registry.holds(pair, token));
        assertTrue(registry.release(pair, token));
        assertTrue(registry.lease(pair).isEmpty());
        assertFalse(registry.release(pair, token));
    }

    @Test
    void withLeaseRunsOnlyForTheLiveHolder() throws Exception {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));

        assertEquals(1, (int) registry.<Integer>withLease(pair, token, connection -> 1));
        assertEquals(2, (int) registry.<Integer>withLease(pair, ORIGIN_SAE, token, connection -> 2));
        assertThrows(PairLockLostException.class,
                () -> registry.withLease(pair, PEER_SAE, token, connection -> 3), "issuer must match");
        assertThrows(PairLockLostException.class,
                () -> registry.withLease(pair, PairLockRegistry.newToken(), connection -> 4));
        clock.addAndGet(LEASE.toNanos());
        AtomicBoolean ran = new AtomicBoolean();
        assertThrows(PairLockLostException.class, () -> registry.withLease(pair, token, connection -> {
            ran.set(true);
            return 5;
        }));
        assertFalse(ran.get());
    }

    @Test
    void withLeaseRollsBackOnFailure() throws Exception {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        assertThrows(SQLException.class, () -> registry.withLease(pair, token, connection -> {
            new ClientRecordStateRepository().upsert(connection, HASH_1, HASH_2,
                    new AtomicRecordStateMap.RecordMetadata(Instant.now(),
                            AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE,
                            PEER_SAE, ORIGIN_SAE, token, SaeFixtures.padPlain()));
            throw new SQLException("boom");
        }));
        assertEquals(0, SaeFixtures.countRecords(SQLITE.origin()));
        assertTrue(registry.holds(pair, token));
    }

    @Test
    void withFreePairSkipsALockedPairAndRunsOnAFreeOrExpiredOne() throws Exception {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        assertEquals(Optional.empty(), registry.withFreePair(pair, connection -> 1));
        clock.addAndGet(LEASE.toNanos());
        assertEquals(Optional.of(2), registry.withFreePair(pair, connection -> 2));
        assertEquals(Optional.of(3), registry.withFreePair(PairKey.of(HASH_2, "c".repeat(64)), connection -> 3));
    }

    /** Two pairs with equal hashCode, so they always share a ConcurrentHashMap bin. */
    private static final PairKey COLLIDING_A = new PairKey("Aa", "zz");
    private static final PairKey COLLIDING_B = new PairKey("BB", "zz");

    @Test
    void slowTransactionOnOnePairDoesNotBlockACollidingPair() throws Exception {
        assertEquals(COLLIDING_A.hashCode(), COLLIDING_B.hashCode());
        String tokenA = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(COLLIDING_A, ORIGIN_SAE, tokenA));
        CountDownLatch inTx = new CountDownLatch(1);
        CountDownLatch finish = new CountDownLatch(1);
        CompletableFuture<Integer> slowTx = CompletableFuture.supplyAsync(() -> {
            try {
                return registry.<Integer>withLease(COLLIDING_A, tokenA, connection -> {
                    inTx.countDown();
                    try {
                        assertTrue(finish.await(30, TimeUnit.SECONDS));
                    } catch (InterruptedException ex) {
                        throw new SQLException(ex);
                    }
                    return 7;
                });
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
        try {
            assertTrue(inTx.await(10, TimeUnit.SECONDS));

            // pair B: every lock operation completes while A's transaction is still open
            CompletableFuture<Boolean> otherPair = CompletableFuture.supplyAsync(() -> {
                String tokenB = PairLockRegistry.newToken();
                return registry.tryAcquire(COLLIDING_B, PEER_SAE, tokenB)
                        && registry.renew(COLLIDING_B, tokenB)
                        && registry.holds(COLLIDING_B, tokenB)
                        && registry.release(COLLIDING_B, tokenB);
            });
            assertTrue(otherPair.get(5, TimeUnit.SECONDS));
            assertFalse(slowTx.isDone());

            // pair A: renew and release wait for A's transaction
            CompletableFuture<Boolean> renewA = CompletableFuture.supplyAsync(() -> registry.renew(COLLIDING_A, tokenA));
            assertThrows(TimeoutException.class, () -> renewA.get(300, TimeUnit.MILLISECONDS));
            CompletableFuture<Boolean> releaseA = CompletableFuture.supplyAsync(() -> registry.release(COLLIDING_A, tokenA));
            assertThrows(TimeoutException.class, () -> releaseA.get(300, TimeUnit.MILLISECONDS));

            finish.countDown();
            assertEquals(7, (int) slowTx.get(10, TimeUnit.SECONDS));
            renewA.get(10, TimeUnit.SECONDS); // true or false depending on whether release ran first
            assertTrue(releaseA.get(10, TimeUnit.SECONDS));
            assertFalse(registry.holds(COLLIDING_A, tokenA));
        } finally {
            finish.countDown();
        }
    }

    @Test
    void transactionSeesNoLeaseChangeUntilItCommits() throws Exception {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        CountDownLatch inTx = new CountDownLatch(1);
        CountDownLatch finish = new CountDownLatch(1);
        CompletableFuture<Boolean> tx = CompletableFuture.supplyAsync(() -> {
            try {
                return registry.<Boolean>withLease(pair, token, connection -> {
                    inTx.countDown();
                    try {
                        finish.await(30, TimeUnit.SECONDS);
                    } catch (InterruptedException ex) {
                        throw new SQLException(ex);
                    }
                    return registry.holds(pair, token);
                });
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
        assertTrue(inTx.await(10, TimeUnit.SECONDS));
        CompletableFuture<Boolean> release = CompletableFuture.supplyAsync(() -> registry.release(pair, token));
        assertThrows(TimeoutException.class, () -> release.get(300, TimeUnit.MILLISECONDS));
        finish.countDown();
        assertTrue(tx.get(10, TimeUnit.SECONDS), "the lease was still held at the end of the transaction");
        assertTrue(release.get(10, TimeUnit.SECONDS));
        assertFalse(registry.holds(pair, token));
    }

    @Test
    void pairSlotsDoNotLeak() throws Exception {
        String token = PairLockRegistry.newToken();
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, token));
        assertEquals(1, registry.slotCount());
        assertTrue(registry.release(pair, token));
        assertEquals(0, registry.slotCount());

        assertFalse(registry.renew(pair, token));
        assertFalse(registry.release(pair, token));
        assertThrows(PairLockLostException.class, () -> registry.withLease(pair, token, connection -> 1));
        assertEquals(Optional.of(1), registry.withFreePair(pair, connection -> 1));
        assertEquals(0, registry.slotCount());

        // an abandoned lease is swept once it expires
        assertTrue(registry.tryAcquire(pair, ORIGIN_SAE, PairLockRegistry.newToken()));
        registry.sweepExpired();
        assertEquals(1, registry.slotCount());
        clock.addAndGet(LEASE.toNanos());
        registry.sweepExpired();
        assertEquals(0, registry.slotCount());
    }
}
