package fel.cvut.node.pairlock;

/** An SAE refused a pair lock because another operation holds it. */
public final class PairBusyException extends Exception {

    private static final long serialVersionUID = 1L;

    public static final String BUSY_MESSAGE =
            "Another operation for this device pair is in progress on an SAE. Retry later.";

    public PairBusyException() {
        super(BUSY_MESSAGE);
    }
}
