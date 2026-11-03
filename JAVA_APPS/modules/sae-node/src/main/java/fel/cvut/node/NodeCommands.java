package fel.cvut.node;

import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * Contract for inter-node RMI calls. The calling SAE is always the identity of the pinned mTLS
 * peer certificate ({@code RmiCallerContext}), never an argument.
 *
 * <p>Pair locks: {@link #lockPair}, {@link #renewPair} and {@link #releasePair} operate on the
 * callee's in-memory lease for the (sorted) client pair; the issuer of a lease is the caller.
 * Writes ({@link #insert}, {@link #deleteRecord}) run only under the caller's live lease with
 * the given token.
 */
public interface NodeCommands extends Remote {
    String ping(Address from) throws RemoteException;

    /** The stored row of the pair in the given orientation, or {@code null}. */
    AtomicRecordStateMap.RecordMetadata getRecordMetadata(String clientHash1, String clientHash2)
            throws RemoteException;

    /**
     * Takes the pair lease for the caller: succeeds when the pair is free, its lease expired, or
     * the lease is the caller's own (the token is replaced). Refused ({@code false}) otherwise.
     */
    boolean lockPair(String clientHash1, String clientHash2, String token) throws RemoteException;

    /** Extends the lease by five minutes only when {@code token} holds it and it has not expired. */
    boolean renewPair(String clientHash1, String clientHash2, String token) throws RemoteException;

    /** Removes the lease only when {@code token} holds it. */
    boolean releasePair(String clientHash1, String clientHash2, String token) throws RemoteException;

    /**
     * Peer half of a new share. The header is in the callee's orientation and its {@code saeId}
     * must be the caller (the origin); the payload holds the KME key IDs. The callee resolves the
     * IDs at its KME, then writes {@code KEYS_AVAILABLE} with {@code token} and the key material
     * in one transaction under the caller's lease.
     *
     * @throws PairLockLostException the caller's lease with {@code token} is not held; nothing written
     */
    void insert(ClientRecord clientRecord, String token) throws RemoteException, PairLockLostException;

    /**
     * Compare-and-delete under the caller's lease {@code leaseToken}: deletes the pair's row only
     * when it still carries {@code rowToken}.
     *
     * @throws PairLockLostException the caller's lease with {@code leaseToken} is not held
     */
    AtomicRecordStateMap.DeleteOutcome deleteRecord(
            String clientHash1, String clientHash2, String leaseToken, String rowToken)
            throws RemoteException, PairLockLostException;
}
