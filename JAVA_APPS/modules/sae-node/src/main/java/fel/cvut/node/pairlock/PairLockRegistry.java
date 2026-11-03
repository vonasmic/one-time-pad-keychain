package fel.cvut.node.pairlock;

import javax.sql.DataSource;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/**
 * In-memory pair locks of one SAE. A lease is {issuer SAE, token, expiry}; it lives
 * {@link #LEASE_DURATION} unless renewed.
 *
 * <p>Every pair in use has its own {@link Slot}: a {@link ReentrantLock} and the current lease.
 * Acquire, renew, release and the guarded database transactions of {@link #withLease} and
 * {@link #withFreePair} all run under that pair's lock, so the token/expiry check and the
 * transaction are one critical section per pair: a lease cannot expire (its expiry is checked
 * once at the start and the renewal/replacement paths wait), be replaced or be released between
 * the check and the commit. Only the same pair serialises; the {@link ConcurrentHashMap} itself
 * is touched only for short slot lookups and reference counting and never waits on SQLite, so a
 * slow transaction on one pair never blocks a pair that shares its hash bin.
 *
 * <p>Slots do not leak: a slot is removed (inside {@code compute}) when its last user leaves and
 * the pair has no live lease. A slot whose lease simply ran out without a release (an operation
 * that died) is swept by {@link #sweepExpired()}, which runs every {@link #SWEEP_EVERY}
 * acquisitions; at most the pairs with a live or recently expired lease have a slot.
 *
 * <p>Every write of a share row ({@code client_record_state} and its key material) goes through
 * {@link #withLease} (or {@link #withFreePair} for retention). The transaction inside is short;
 * never call RMI from it.
 *
 * <p>Locks are not persisted: after a restart every pair is free.
 */
public final class PairLockRegistry {

    public static final Duration LEASE_DURATION = Duration.ofMinutes(5);

    /** {@link #sweepExpired()} runs once per this many {@link #tryAcquire} calls. */
    static final int SWEEP_EVERY = 256;

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Per-pair lock and lease. {@code users} is only read and written inside {@code compute}. */
    private static final class Slot {
        final ReentrantLock lock = new ReentrantLock();
        /** Written only while holding {@link #lock}; volatile for the lock-free readers. */
        volatile Lease lease;
        int users;
    }

    private final ConcurrentHashMap<PairKey, Slot> slots = new ConcurrentHashMap<>();
    private final AtomicInteger acquisitions = new AtomicInteger();
    private final DataSource dataSource;
    private final long leaseNanos;
    private final LongSupplier nanoClock;

    public record Lease(String issuerSaeId, String token, long expiresAtNanos) {
    }

    @FunctionalInterface
    public interface TxWork<T> {
        T run(Connection connection) throws SQLException;
    }

    @FunctionalInterface
    private interface Locked<T, E extends Exception> {
        T run(Slot slot) throws E;
    }

    public PairLockRegistry(DataSource dataSource) {
        this(dataSource, LEASE_DURATION, System::nanoTime);
    }

    public PairLockRegistry(DataSource dataSource, Duration leaseDuration, LongSupplier nanoClock) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource must not be null");
        Objects.requireNonNull(leaseDuration, "leaseDuration must not be null");
        if (leaseDuration.isZero() || leaseDuration.isNegative()) {
            throw new IllegalArgumentException("leaseDuration must be positive");
        }
        this.leaseNanos = leaseDuration.toNanos();
        this.nanoClock = Objects.requireNonNull(nanoClock, "nanoClock must not be null");
    }

    /** A fresh 128-bit token from {@link SecureRandom}, hex encoded. */
    public static String newToken() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    /**
     * Takes the lease when the pair is free, its lease expired, or the lease belongs to the same
     * issuer (an issuer runs one session at a time, so its older lease is from an ended attempt;
     * the token is replaced). Refused otherwise. Waits while a transaction of the same pair runs.
     */
    public boolean tryAcquire(PairKey pair, String issuerSaeId, String token) {
        Objects.requireNonNull(pair, "pair must not be null");
        requireText(issuerSaeId, "issuerSaeId");
        requireText(token, "token");
        if (acquisitions.incrementAndGet() % SWEEP_EVERY == 0) {
            sweepExpired();
        }
        return locked(pair, slot -> {
            Lease current = slot.lease;
            long now = nanoClock.getAsLong();
            if (current == null || expired(current, now) || current.issuerSaeId().equals(issuerSaeId)) {
                slot.lease = new Lease(issuerSaeId, token, now + leaseNanos);
                return true;
            }
            return false;
        });
    }

    /**
     * Extends the lease by {@link #LEASE_DURATION} only when {@code token} holds it and it has
     * not expired. Waits while a transaction of the same pair runs.
     */
    public boolean renew(PairKey pair, String token) {
        Objects.requireNonNull(pair, "pair must not be null");
        requireText(token, "token");
        if (!slots.containsKey(pair)) {
            return false;
        }
        return locked(pair, slot -> {
            Lease current = slot.lease;
            if (current == null) {
                return false;
            }
            long now = nanoClock.getAsLong();
            if (expired(current, now)) {
                slot.lease = null;
                return false;
            }
            if (current.token().equals(token)) {
                slot.lease = new Lease(current.issuerSaeId(), token, now + leaseNanos);
                return true;
            }
            return false;
        });
    }

    /** Removes the lease only when {@code token} holds it. Waits while a transaction of the same pair runs. */
    public boolean release(PairKey pair, String token) {
        Objects.requireNonNull(pair, "pair must not be null");
        requireText(token, "token");
        if (!slots.containsKey(pair)) {
            return false;
        }
        return locked(pair, slot -> {
            Lease current = slot.lease;
            if (current == null) {
                return false;
            }
            if (current.token().equals(token)) {
                slot.lease = null;
                return true;
            }
            if (expired(current, nanoClock.getAsLong())) {
                slot.lease = null;
            }
            return false;
        });
    }

    /** {@code true} when {@code token} holds a live lease on the pair (a snapshot; does not wait). */
    public boolean holds(PairKey pair, String token) {
        Lease lease = currentLease(pair);
        return lease != null && lease.token().equals(token) && !expired(lease, nanoClock.getAsLong());
    }

    /** The live lease of the pair, if any (a snapshot; does not wait). */
    public Optional<Lease> lease(PairKey pair) {
        Lease lease = currentLease(pair);
        if (lease == null || expired(lease, nanoClock.getAsLong())) {
            return Optional.empty();
        }
        return Optional.of(lease);
    }

    /**
     * Runs {@code work} in one short {@code BEGIN IMMEDIATE} transaction while {@code token}
     * holds a live lease on the pair. Verification and transaction are one atomic step under the
     * pair's lock: the lease cannot be replaced, renewed or released while the transaction runs.
     *
     * @throws PairLockLostException the token does not hold a live lease; nothing ran
     */
    public <T> T withLease(PairKey pair, String token, TxWork<T> work)
            throws PairLockLostException, SQLException {
        return withLease(pair, null, token, work);
    }

    /**
     * As {@link #withLease(PairKey, String, TxWork)}, and the lease must also have been taken
     * by {@code issuerSaeId} (the authenticated RMI caller), when not {@code null}.
     */
    public <T> T withLease(PairKey pair, String issuerSaeId, String token, TxWork<T> work)
            throws PairLockLostException, SQLException {
        Objects.requireNonNull(pair, "pair must not be null");
        requireText(token, "token");
        Objects.requireNonNull(work, "work must not be null");
        if (!slots.containsKey(pair)) {
            throw lost();
        }
        Object[] result = new Object[1];
        SQLException[] failure = new SQLException[1];
        boolean held = locked(pair, slot -> {
            Lease current = slot.lease;
            if (current == null || !current.token().equals(token) || expired(current, nanoClock.getAsLong())
                    || (issuerSaeId != null && !current.issuerSaeId().equals(issuerSaeId))) {
                return false;
            }
            try {
                result[0] = runTransaction(work);
            } catch (SQLException ex) {
                failure[0] = ex;
            }
            return true;
        });
        if (!held) {
            throw lost();
        }
        if (failure[0] != null) {
            throw failure[0];
        }
        @SuppressWarnings("unchecked")
        T typed = (T) result[0];
        return typed;
    }

    /**
     * Runs {@code work} in one transaction only while nobody holds a live lease on the pair
     * (used by the retention purge, which must not touch a share an operation is working on).
     * The pair's lock is held for the transaction, so no lease can be taken meanwhile.
     *
     * @return the result, or empty when the pair is locked and nothing ran
     */
    public <T> Optional<T> withFreePair(PairKey pair, TxWork<T> work) throws SQLException {
        Objects.requireNonNull(pair, "pair must not be null");
        Objects.requireNonNull(work, "work must not be null");
        Object[] result = new Object[1];
        boolean ran = locked(pair, slot -> {
            Lease current = slot.lease;
            if (current != null && !expired(current, nanoClock.getAsLong())) {
                return false;
            }
            slot.lease = null;
            result[0] = runTransaction(work);
            return true;
        });
        if (!ran) {
            return Optional.empty();
        }
        @SuppressWarnings("unchecked")
        T typed = (T) result[0];
        return Optional.ofNullable(typed);
    }

    /** Drops the slots of pairs nobody uses whose lease has expired. Never waits on a pair lock. */
    public void sweepExpired() {
        long now = nanoClock.getAsLong();
        for (PairKey pair : slots.keySet()) {
            slots.computeIfPresent(pair, (key, slot) -> {
                Lease lease = slot.lease;
                return slot.users == 0 && (lease == null || expired(lease, now)) ? null : slot;
            });
        }
    }

    /** Number of pair slots currently allocated (for tests and monitoring). */
    public int slotCount() {
        return slots.size();
    }

    /**
     * Runs {@code body} holding the pair's lock. The slot is created or pinned inside a short
     * {@code compute} (no waiting there), the lock is taken outside the map, and on the way out
     * the slot is unpinned and removed when nobody else uses it and the pair has no live lease.
     */
    private <T, E extends Exception> T locked(PairKey pair, Locked<T, E> body) throws E {
        Slot slot = slots.compute(pair, (key, current) -> {
            Slot pinned = current == null ? new Slot() : current;
            pinned.users++;
            return pinned;
        });
        slot.lock.lock();
        try {
            return body.run(slot);
        } finally {
            slot.lock.unlock();
            slots.compute(pair, (key, current) -> {
                // current == slot: a pinned slot is never removed
                current.users--;
                Lease lease = current.lease;
                boolean idle = current.users == 0
                        && (lease == null || expired(lease, nanoClock.getAsLong()));
                return idle ? null : current;
            });
        }
    }

    private Lease currentLease(PairKey pair) {
        Slot slot = slots.get(pair);
        return slot == null ? null : slot.lease;
    }

    private static PairLockLostException lost() {
        return new PairLockLostException("Pair lease not held by this operation.");
    }

    private <T> T runTransaction(TxWork<T> work) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            // DB.openPool configures BEGIN IMMEDIATE for non-autocommit transactions.
            connection.setAutoCommit(false);
            try {
                T value = work.run(connection);
                connection.commit();
                return value;
            } catch (SQLException | RuntimeException ex) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackEx) {
                    ex.addSuppressed(rollbackEx);
                }
                throw ex;
            } finally {
                connection.setAutoCommit(true);
            }
        }
    }

    private static boolean expired(Lease lease, long now) {
        return now - lease.expiresAtNanos() >= 0;
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be null or blank");
        }
    }
}
