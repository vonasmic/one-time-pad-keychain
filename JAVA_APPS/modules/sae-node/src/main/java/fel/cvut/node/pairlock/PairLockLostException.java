package fel.cvut.node.pairlock;

/**
 * The operation no longer holds the pair lease it needs (token unknown, replaced or expired), or
 * renewing a lease failed. Thrown locally and across RMI.
 */
public final class PairLockLostException extends Exception {

    private static final long serialVersionUID = 1L;

    public static final String ABORT_MESSAGE =
            "The lock for this device pair was lost on an SAE. The operation was aborted. Retry.";

    public PairLockLostException(String message) {
        super(message);
    }

    public PairLockLostException(String message, Throwable cause) {
        super(message, cause);
    }
}
