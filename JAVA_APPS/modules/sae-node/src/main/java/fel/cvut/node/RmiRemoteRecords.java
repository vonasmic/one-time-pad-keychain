package fel.cvut.node;

import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLocks;
import fel.cvut.node.recordManager.AtomicRecordStateMap;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.Objects;

/**
 * {@link ProvisionSession.RemoteRecords} of a node: rows of this SAE are read and deleted
 * locally, rows of other SAEs over RMI (the callee binds this SAE as the caller from mTLS).
 * Hashes are always in the orientation stored on the addressed SAE.
 */
public final class RmiRemoteRecords implements ProvisionSession.RemoteRecords {

    private final String selfSaeId;
    private final AtomicRecordStateMap localMap;
    private final PairLocks.Remote remote;

    public RmiRemoteRecords(String selfSaeId, AtomicRecordStateMap localMap, PairLocks.Remote remote) {
        this.selfSaeId = Objects.requireNonNull(selfSaeId, "selfSaeId must not be null");
        this.localMap = Objects.requireNonNull(localMap, "localMap must not be null");
        this.remote = Objects.requireNonNull(remote, "remote must not be null");
    }

    @Override
    public AtomicRecordStateMap.RecordMetadata get(String saeId, String clientHash1, String clientHash2)
            throws RemoteException, NotBoundException {
        if (Objects.equals(saeId, selfSaeId)) {
            return localMap.get(clientHash1, clientHash2).orElse(null);
        }
        return remote.connect(saeId).getRecordMetadata(clientHash1, clientHash2);
    }

    @Override
    public AtomicRecordStateMap.DeleteOutcome delete(
            String saeId, String clientHash1, String clientHash2, String leaseToken, String rowToken)
            throws RemoteException, NotBoundException, PairLockLostException {
        if (Objects.equals(saeId, selfSaeId)) {
            return localMap.deleteIfToken(leaseToken, clientHash1, clientHash2, rowToken);
        }
        return remote.connect(saeId).deleteRecord(clientHash1, clientHash2, leaseToken, rowToken);
    }
}
