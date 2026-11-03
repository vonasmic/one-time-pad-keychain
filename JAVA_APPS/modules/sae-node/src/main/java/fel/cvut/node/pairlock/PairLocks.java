package fel.cvut.node.pairlock;

import fel.cvut.node.NodeCommands;

import java.math.BigInteger;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.time.Duration;
import java.util.Comparator;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Acquires both pair locks of an operation in a fixed order: the SAE with the lower ID first,
 * then the higher. When the second lock is refused, the first is released by token and the
 * operation fails at once ({@link PairBusyException}); nobody waits and nobody takes over.
 */
public final class PairLocks implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(PairLocks.class.getName());

    public static final Duration RENEW_INTERVAL = Duration.ofSeconds(60);

    /** Order of SAE IDs: numeric when both parse as integers, lexicographic otherwise. */
    public static final Comparator<String> SAE_ORDER = PairLocks::compareSaeIds;

    /** Resolves the RMI stub of another SAE. */
    @FunctionalInterface
    public interface Remote {
        NodeCommands connect(String saeId) throws RemoteException, NotBoundException;
    }

    private final String selfSaeId;
    private final PairLockRegistry registry;
    private final Remote remote;
    private final ScheduledExecutorService scheduler;
    private final boolean ownsScheduler;
    private final Duration renewInterval;

    public PairLocks(String selfSaeId, PairLockRegistry registry, Remote remote) {
        this(selfSaeId, registry, remote, Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "pair-lock-renewal");
            thread.setDaemon(true);
            return thread;
        }), true, RENEW_INTERVAL);
    }

    public PairLocks(String selfSaeId, PairLockRegistry registry, Remote remote,
                     ScheduledExecutorService scheduler, Duration renewInterval) {
        this(selfSaeId, registry, remote, scheduler, false, renewInterval);
    }

    private PairLocks(String selfSaeId, PairLockRegistry registry, Remote remote,
                      ScheduledExecutorService scheduler, boolean ownsScheduler, Duration renewInterval) {
        this.selfSaeId = Objects.requireNonNull(selfSaeId, "selfSaeId must not be null");
        this.registry = Objects.requireNonNull(registry, "registry must not be null");
        this.remote = Objects.requireNonNull(remote, "remote must not be null");
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler must not be null");
        this.ownsScheduler = ownsScheduler;
        this.renewInterval = Objects.requireNonNull(renewInterval, "renewInterval must not be null");
    }

    public PairLockRegistry registry() {
        return registry;
    }

    /**
     * Locks the pair on {@code saeA} and {@code saeB} with one fresh token, lower SAE ID first,
     * and starts renewing both. The hashes are given in this SAE's orientation; the lock key is
     * the sorted pair, so orientation does not matter.
     *
     * @throws PairBusyException one SAE refused; nothing stays locked
     */
    public PairOperation acquire(String saeA, String saeB, String clientHash1, String clientHash2)
            throws PairBusyException, RemoteException, NotBoundException {
        if (saeA.equals(saeB)) {
            throw new IllegalArgumentException("a pair operation needs two different SAEs");
        }
        PairLockEndpoint a = endpoint(saeA);
        PairLockEndpoint b = endpoint(saeB);
        PairLockEndpoint first = SAE_ORDER.compare(saeA, saeB) < 0 ? a : b;
        PairLockEndpoint second = first == a ? b : a;
        String token = PairLockRegistry.newToken();

        lockOrFail(first, clientHash1, clientHash2, token, null);
        lockOrFail(second, clientHash1, clientHash2, token, first);
        PairOperation operation = new PairOperation(token, clientHash1, clientHash2, first, second);
        operation.startRenewals(scheduler, renewInterval);
        return operation;
    }

    private static void lockOrFail(PairLockEndpoint endpoint, String h1, String h2, String token,
                                   PairLockEndpoint alreadyLocked)
            throws PairBusyException, RemoteException, NotBoundException {
        boolean locked;
        try {
            locked = endpoint.lock(h1, h2, token);
        } catch (RemoteException | NotBoundException | RuntimeException ex) {
            // The lock may have been taken before the reply was lost; release by token.
            releaseQuietly(endpoint, h1, h2, token);
            releaseQuietly(alreadyLocked, h1, h2, token);
            throw ex;
        }
        if (!locked) {
            releaseQuietly(alreadyLocked, h1, h2, token);
            LOG.info("Pair lock refused by SAE " + endpoint.saeId());
            throw new PairBusyException();
        }
    }

    static void releaseQuietly(PairLockEndpoint endpoint, String h1, String h2, String token) {
        if (endpoint == null) {
            return;
        }
        try {
            endpoint.release(h1, h2, token);
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "Releasing pair lock on SAE " + endpoint.saeId()
                    + " failed (it expires on its own): " + ex.getMessage(), ex);
        }
    }

    private PairLockEndpoint endpoint(String saeId) {
        if (saeId.equals(selfSaeId)) {
            return new LocalEndpoint(selfSaeId, registry);
        }
        return new RemoteEndpoint(saeId, remote);
    }

    @Override
    public void close() {
        if (ownsScheduler) {
            scheduler.shutdownNow();
        }
    }

    static int compareSaeIds(String left, String right) {
        try {
            return new BigInteger(left).compareTo(new BigInteger(right));
        } catch (NumberFormatException ex) {
            return left.compareTo(right);
        }
    }

    private record LocalEndpoint(String saeId, PairLockRegistry registry) implements PairLockEndpoint {
        @Override
        public boolean lock(String h1, String h2, String token) {
            return registry.tryAcquire(PairKey.of(h1, h2), saeId, token);
        }

        @Override
        public boolean renew(String h1, String h2, String token) {
            return registry.renew(PairKey.of(h1, h2), token);
        }

        @Override
        public boolean release(String h1, String h2, String token) {
            return registry.release(PairKey.of(h1, h2), token);
        }

        @Override
        public boolean local() {
            return true;
        }
    }

    private record RemoteEndpoint(String saeId, Remote remote) implements PairLockEndpoint {
        @Override
        public boolean lock(String h1, String h2, String token) throws RemoteException, NotBoundException {
            return remote.connect(saeId).lockPair(h2, h1, token);
        }

        @Override
        public boolean renew(String h1, String h2, String token) throws RemoteException, NotBoundException {
            return remote.connect(saeId).renewPair(h2, h1, token);
        }

        @Override
        public boolean release(String h1, String h2, String token) throws RemoteException, NotBoundException {
            return remote.connect(saeId).releasePair(h2, h1, token);
        }

        @Override
        public boolean local() {
            return false;
        }
    }
}
