package fel.cvut.utimaco;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Serializes all HSM access in one JVM.
 *
 * <p>Two Utimaco APIs talk to the same device:
 * <ul>
 *   <li><b>PQMI (CXI)</b> — opens a short-lived CXI connection per operation
 *       ({@link Pqmi#withSession}), then closes it.</li>
 *   <li><b>CryptoServer JCE</b> — one logged-in {@code CryptoServerProvider} for the
 *       JVM lifetime after {@link fel.cvut.tls.TlsProviders#install} (QKD mTLS sign,
 *       AES-GCM, keystore).</li>
 * </ul>
 *
 * <p>Concurrent overlap (e.g. a PQMI CXI window on one thread while JCE crypto runs on
 * another) can corrupt device/session state on the HSM. Every PQMI op and JCE HSM call
 * must go through this gate.
 */
public final class HsmGate {

    private static final ReentrantLock LOCK = new ReentrantLock();
    private static final long LOCK_TIMEOUT_SECONDS = 10;

    private HsmGate() {
    }

    public static void run(HsmAction action) throws Exception {
        if (!LOCK.tryLock(LOCK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            throw new IllegalStateException(
                    "Timed out waiting for HSM gate lock after " + LOCK_TIMEOUT_SECONDS + " seconds");
        }
        try {
            action.run();
        } finally {
            LOCK.unlock();
        }
    }

    public static <T> T call(HsmCallable<T> callable) throws Exception {
        if (!LOCK.tryLock(LOCK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            throw new IllegalStateException(
                    "Timed out waiting for HSM gate lock after " + LOCK_TIMEOUT_SECONDS + " seconds");
        }
        try {
            return callable.call();
        } finally {
            LOCK.unlock();
        }
    }

    @FunctionalInterface
    public interface HsmAction {
        void run() throws Exception;
    }

    @FunctionalInterface
    public interface HsmCallable<T> {
        T call() throws Exception;
    }
}
