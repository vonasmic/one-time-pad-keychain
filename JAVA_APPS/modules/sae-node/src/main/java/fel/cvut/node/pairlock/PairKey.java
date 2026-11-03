package fel.cvut.node.pairlock;

/**
 * Key of a pair lock: the two client hashes in sorted order, so both SAEs of a share (which
 * store the pair in opposite orientation) lock the same key.
 */
public record PairKey(String low, String high) {

    public PairKey {
        requireHash(low, "low");
        requireHash(high, "high");
        if (low.compareTo(high) > 0) {
            throw new IllegalArgumentException("low must not sort after high");
        }
    }

    public static PairKey of(String clientHash1, String clientHash2) {
        requireHash(clientHash1, "clientHash1");
        requireHash(clientHash2, "clientHash2");
        return clientHash1.compareTo(clientHash2) <= 0
                ? new PairKey(clientHash1, clientHash2)
                : new PairKey(clientHash2, clientHash1);
    }

    private static void requireHash(String hash, String name) {
        if (hash == null || hash.isBlank()) {
            throw new IllegalArgumentException(name + " must not be null or blank");
        }
    }
}
