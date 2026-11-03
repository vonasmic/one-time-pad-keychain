package fel.cvut.node.pairlock;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * One operation holding the pair lock on two SAEs under one token. A background task renews
 * both leases every {@link PairLocks#RENEW_INTERVAL}; a failed renewal aborts the operation and
 * runs the abort hook (the node closes the device session). {@link #checkpoint()} is the gap
 * guard: it renews both leases synchronously and must succeed before the next step after any
 * delay the background renewals do not vouch for.
 */
public final class PairOperation implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(PairOperation.class.getName());

    private final String token;
    private final String clientHash1;
    private final String clientHash2;
    private final PairLockEndpoint first;
    private final PairLockEndpoint second;
    private final Object renewLock = new Object();
    private volatile String abortReason;
    private volatile Runnable abortHook;
    private volatile boolean closed;
    private ScheduledFuture<?> renewal;

    PairOperation(String token, String clientHash1, String clientHash2,
                  PairLockEndpoint first, PairLockEndpoint second) {
        this.token = Objects.requireNonNull(token, "token must not be null");
        this.clientHash1 = Objects.requireNonNull(clientHash1, "clientHash1 must not be null");
        this.clientHash2 = Objects.requireNonNull(clientHash2, "clientHash2 must not be null");
        this.first = Objects.requireNonNull(first, "first must not be null");
        this.second = Objects.requireNonNull(second, "second must not be null");
    }

    public String token() {
        return token;
    }

    /** SAE locked first (lower ID). */
    public String firstSaeId() {
        return first.saeId();
    }

    public String secondSaeId() {
        return second.saeId();
    }

    synchronized void startRenewals(ScheduledExecutorService scheduler, Duration interval) {
        long millis = interval.toMillis();
        renewal = scheduler.scheduleWithFixedDelay(this::scheduledRenew, millis, millis, TimeUnit.MILLISECONDS);
    }

    /** Runs {@code hook} when the operation aborts (at once if it already has). */
    public void onAbort(Runnable hook) {
        abortHook = hook;
        if (abortReason != null && hook != null) {
            runHook(hook);
        }
    }

    public boolean isAborted() {
        return abortReason != null;
    }

    public String abortReason() {
        return abortReason;
    }

    /**
     * Gap guard: renews both leases now. Throws (and aborts the operation) when the operation
     * was aborted, closed, or either SAE no longer holds the token.
     */
    public void checkpoint() throws PairLockLostException {
        if (abortReason != null) {
            throw new PairLockLostException(PairLockLostException.ABORT_MESSAGE + " (" + abortReason + ")");
        }
        if (closed) {
            throw new PairLockLostException("Pair operation already closed.");
        }
        String failure = renewBoth();
        if (failure != null) {
            abort(failure);
            throw new PairLockLostException(PairLockLostException.ABORT_MESSAGE + " (" + failure + ")");
        }
    }

    /** @return {@code null} when both renewed, otherwise the reason */
    private String renewBoth() {
        synchronized (renewLock) {
            for (PairLockEndpoint endpoint : new PairLockEndpoint[]{first, second}) {
                try {
                    if (!endpoint.renew(clientHash1, clientHash2, token)) {
                        return "SAE " + endpoint.saeId() + " no longer holds the lease";
                    }
                } catch (Exception ex) {
                    LOG.log(Level.WARNING, "Renewing pair lock on SAE " + endpoint.saeId()
                            + " failed: " + ex.getMessage(), ex);
                    return "renewal on SAE " + endpoint.saeId() + " failed: " + ex.getMessage();
                }
            }
            return null;
        }
    }

    private void scheduledRenew() {
        if (closed || abortReason != null) {
            return;
        }
        String failure = renewBoth();
        if (failure != null && !closed) {
            abort(failure);
        }
    }

    /** Aborts the operation: stops renewals and runs the abort hook once. */
    public void abort(String reason) {
        synchronized (this) {
            if (abortReason != null) {
                return;
            }
            abortReason = reason == null ? "aborted" : reason;
            if (renewal != null) {
                renewal.cancel(false);
            }
        }
        LOG.warning("Pair operation aborted: " + abortReason);
        Runnable hook = abortHook;
        if (hook != null) {
            runHook(hook);
        }
    }

    private static void runHook(Runnable hook) {
        try {
            hook.run();
        } catch (RuntimeException ex) {
            LOG.log(Level.WARNING, "Pair operation abort hook failed: " + ex.getMessage(), ex);
        }
    }

    /** Stops renewing and releases both leases by token: remote SAEs first, this SAE last. */
    @Override
    public void close() {
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
            if (renewal != null) {
                renewal.cancel(false);
            }
        }
        synchronized (renewLock) {
            PairLockEndpoint[] order = first.local()
                    ? new PairLockEndpoint[]{second, first}
                    : second.local() ? new PairLockEndpoint[]{first, second}
                    : new PairLockEndpoint[]{second, first};
            for (PairLockEndpoint endpoint : order) {
                PairLocks.releaseQuietly(endpoint, clientHash1, clientHash2, token);
            }
        }
    }
}
