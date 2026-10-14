package fel.cvut.node.interNodeCommunication;

import java.util.Optional;
import java.util.concurrent.Callable;

/**
 * SAE identity of the peer whose RMI call is being dispatched on the current thread.
 *
 * <p>In production the identity is bound by {@link RmiPeerPinning}: every read from an accepted
 * RMI/TLS connection binds the SAE ID that the peer's pinned leaf certificate maps to (see
 * {@link KnownPeers}). JDK RMI reads a call and dispatches it on the same connection thread, so
 * {@link NodeCommandsService} sees the authenticated caller, never a value from the call arguments.
 *
 * <p>{@link #callAs} exists for in-process callers (tests, in-JVM wiring) that bypass TLS.
 */
public final class RmiCallerContext {

    private static final ThreadLocal<String> CALLER = new ThreadLocal<>();

    private RmiCallerContext() {
    }

    /** Authenticated caller SAE ID, or empty when the thread is not serving a pinned RMI peer. */
    public static Optional<String> currentSaeId() {
        return Optional.ofNullable(CALLER.get());
    }

    /** Runs {@code action} with {@code saeId} bound as the caller, restoring the previous binding. */
    public static <T> T callAs(String saeId, Callable<T> action) throws Exception {
        if (saeId == null || saeId.isBlank()) {
            throw new IllegalArgumentException("saeId must not be blank");
        }
        String previous = CALLER.get();
        CALLER.set(saeId);
        try {
            return action.call();
        } finally {
            if (previous == null) {
                CALLER.remove();
            } else {
                CALLER.set(previous);
            }
        }
    }

    static void bind(String saeId) {
        CALLER.set(saeId);
    }

    static void clear() {
        CALLER.remove();
    }
}
