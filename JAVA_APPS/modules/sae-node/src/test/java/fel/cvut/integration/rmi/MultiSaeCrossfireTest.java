package fel.cvut.integration.rmi;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.pairlock.PairBusyException;
import fel.cvut.node.pairlock.PairOperation;
import fel.cvut.node.recordManager.ClientRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Several SAEs originate exchanges at the same moment over in-process RMI with real pair locks:
 * the fixed lock order (lower SAE ID first) never deadlocks, an overlapping operation is refused
 * instead of waiting, and the surviving share always carries one token on both rows.
 */
@Tag("integration")
@Timeout(90)
class MultiSaeCrossfireTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private ProvisionCluster cluster;
    private SaeNode origin;
    private SaeNode peerA;
    private SaeNode peerB;

    @BeforeEach
    void setUp() throws Exception {
        cluster = new ProvisionCluster(SQLITE);
        origin = cluster.origin();
        peerA = cluster.peerA();
        peerB = cluster.peerB();
    }

    @AfterEach
    void tearDown() {
        cluster.close();
    }

    /** One attempt: the side, its hashes (own orientation) and the counterpart. */
    private record Attempt(SaeNode local, String counterpart, String h1, String h2) {
    }

    @Test
    void bothOriginsOfOnePairAtOnceNeverDeadlockAndExactlyOneWins() throws Exception {
        // the two devices of one pair are plugged in at their SAEs at the same time
        List<String> tokens = runOverlapping(List.of(
                new Attempt(origin, peerA.id(), HASH_1, HASH_2),
                new Attempt(peerA, origin.id(), HASH_2, HASH_1)));

        assertEquals(1, tokens.stream().filter(t -> t != null).count(), "exactly one origin wins");
        String winner = tokens.stream().filter(t -> t != null).findFirst().orElseThrow();
        assertConsistent(origin, HASH_1, HASH_2, peerA, winner);
        assertTrue(origin.pairFree(HASH_1, HASH_2) && peerA.pairFree(HASH_2, HASH_1));

        // the refused side retries and replaces the share under both locks
        int loser = tokens.get(0) == null ? 0 : 1;
        Attempt retry = loser == 0
                ? new Attempt(origin, peerA.id(), HASH_1, HASH_2)
                : new Attempt(peerA, origin.id(), HASH_2, HASH_1);
        String newer = exchange(retry);
        assertNotEquals(winner, newer);
        assertConsistent(origin, HASH_1, HASH_2, peerA, newer);
        assertEquals(retry.local().id(), origin.row(HASH_1, HASH_2).orElseThrow().issuingSaeId());
        // key material is stored only at the counterpart of the issuing SAE; the old share's is gone
        SaeNode counterpart = retry.local() == origin ? peerA : origin;
        assertEquals(1, counterpart.keyMaterial());
        assertEquals(0, retry.local().keyMaterial());
    }

    @Test
    void twoSaesOriginatingTowardsOnePeerForTheSamePairAreSerialisedOnThatPeer() throws Exception {
        // sae-1 locks sae-1 then sae-2; sae-3 locks sae-2 then sae-3: both contend on sae-2
        List<String> tokens = runOverlapping(List.of(
                new Attempt(origin, peerA.id(), HASH_1, HASH_2),
                new Attempt(peerB, peerA.id(), HASH_1, HASH_2)));

        assertEquals(1, tokens.stream().filter(t -> t != null).count());
        assertTrue(origin.pairFree(HASH_1, HASH_2));
        assertTrue(peerA.pairFree(HASH_2, HASH_1));
        assertTrue(peerB.pairFree(HASH_1, HASH_2));
        SaeNode winner = tokens.get(0) != null ? origin : peerB;
        SaeNode loser = winner == origin ? peerB : origin;
        assertConsistent(winner, HASH_1, HASH_2, peerA, tokens.get(winner == origin ? 0 : 1));
        assertTrue(loser.isEmpty(), "the refused SAE wrote nothing");
        assertEquals(winner.id(), peerA.row(HASH_2, HASH_1).orElseThrow().saeId());
    }

    @Test
    void disjointPairsAcrossThreeNodesAllSucceedConcurrently() throws Exception {
        String pairB1 = HASH_1.substring(0, 62) + "10";
        String pairC1 = HASH_1.substring(0, 62) + "20";
        List<Attempt> attempts = List.of(
                new Attempt(origin, peerA.id(), HASH_1, HASH_2),
                new Attempt(peerB, peerA.id(), pairB1, HASH_2),
                new Attempt(origin, peerB.id(), pairC1, HASH_2));
        ExecutorService executor = Executors.newFixedThreadPool(attempts.size());
        CyclicBarrier barrier = new CyclicBarrier(attempts.size());
        List<Future<String>> futures = new ArrayList<>();
        try {
            for (Attempt attempt : attempts) {
                futures.add(executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    return exchange(attempt);
                }));
            }
            List<String> tokens = new ArrayList<>();
            for (Future<String> future : futures) {
                tokens.add(future.get(30, TimeUnit.SECONDS));
            }
            assertConsistent(origin, HASH_1, HASH_2, peerA, tokens.get(0));
            assertConsistent(peerB, pairB1, HASH_2, peerA, tokens.get(1));
            assertConsistent(origin, pairC1, HASH_2, peerB, tokens.get(2));
        } finally {
            executor.shutdownNow();
        }
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Starts all attempts together; a winner keeps its locks until every attempt has tried to
     * lock, so the attempts really overlap. Returns per attempt the share token, or {@code null}
     * when it was refused as busy.
     */
    private List<String> runOverlapping(List<Attempt> attempts) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(attempts.size());
        CyclicBarrier barrier = new CyclicBarrier(attempts.size());
        CountDownLatch attempted = new CountDownLatch(attempts.size());
        List<Future<String>> futures = new ArrayList<>();
        try {
            for (Attempt attempt : attempts) {
                futures.add(executor.submit(() -> {
                    barrier.await(15, TimeUnit.SECONDS);
                    PairOperation operation;
                    try {
                        operation = attempt.local().locks.acquire(
                                attempt.local().id(), attempt.counterpart(), attempt.h1(), attempt.h2());
                    } catch (PairBusyException busy) {
                        assertEquals(PairBusyException.BUSY_MESSAGE, busy.getMessage());
                        return null;
                    } finally {
                        attempted.countDown();
                    }
                    try (operation) {
                        assertTrue(attempted.await(15, TimeUnit.SECONDS));
                        return write(attempt, operation);
                    }
                }));
            }
            List<String> tokens = new ArrayList<>();
            for (Future<String> future : futures) {
                tokens.add(future.get(30, TimeUnit.SECONDS));
            }
            return tokens;
        } finally {
            executor.shutdownNow();
        }
    }

    private String exchange(Attempt attempt) throws Exception {
        try (PairOperation operation = attempt.local().locks.acquire(
                attempt.local().id(), attempt.counterpart(), attempt.h1(), attempt.h2())) {
            return write(attempt, operation);
        }
    }

    private static String write(Attempt attempt, PairOperation operation) throws Exception {
        ClientRecord record = SaeFixtures.record(attempt.h1(), attempt.h2(), attempt.counterpart(), List.of());
        var sync = attempt.local().sync();
        ProvisionSession.Exchange.Prepared prepared = sync.prepare(record, SaeFixtures.uplink());
        operation.checkpoint();
        sync.insertPeer(record.withPayload(prepared.keyIds()), operation.token());
        sync.writeOrigin(record.withPayload(prepared.keyIds()), operation.token());
        operation.checkpoint();
        return operation.token();
    }

    /** Both rows of the pair exist and carry the same token. */
    private static void assertConsistent(SaeNode a, String h1, String h2, SaeNode b, String token) {
        assertNotNull(token);
        assertEquals(token, a.row(h1, h2).orElseThrow().token());
        assertEquals(token, b.row(h2, h1).orElseThrow().token());
        assertEquals(b.id(), a.row(h1, h2).orElseThrow().saeId());
        assertEquals(a.id(), b.row(h2, h1).orElseThrow().saeId());
    }
}
