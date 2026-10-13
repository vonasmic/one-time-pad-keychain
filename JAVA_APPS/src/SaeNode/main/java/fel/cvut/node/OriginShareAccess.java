package fel.cvut.node;

import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.Objects;

/**
 * Reads and deletes the issuing SAE's row. Hash arguments are the origin orientation
 * ({@code (clientHash1, clientHash2)} as stored on the origin).
 */
public interface OriginShareAccess {

    AtomicRecordStateMap.RecordMetadata get(String saeId, String clientHash1, String clientHash2)
            throws RemoteException, NotBoundException;

    AtomicRecordStateMap.RecordMetadata remove(String saeId, String clientHash1, String clientHash2)
            throws RemoteException, NotBoundException;

    static OriginShareAccess unreachable() {
        return new OriginShareAccess() {
            @Override
            public AtomicRecordStateMap.RecordMetadata get(
                    String saeId, String clientHash1, String clientHash2) throws RemoteException {
                throw new RemoteException("origin SAE unreachable");
            }

            @Override
            public AtomicRecordStateMap.RecordMetadata remove(
                    String saeId, String clientHash1, String clientHash2) throws RemoteException {
                throw new RemoteException("origin SAE unreachable");
            }
        };
    }

    static OriginShareAccess viaRmi(RmiManager rmiManager) {
        Objects.requireNonNull(rmiManager, "rmiManager must not be null");
        return new OriginShareAccess() {
            @Override
            public AtomicRecordStateMap.RecordMetadata get(
                    String saeId, String clientHash1, String clientHash2)
                    throws RemoteException, NotBoundException {
                return rmiManager.connectBySaeId(saeId).getRecordMetadata(clientHash1, clientHash2);
            }

            @Override
            public AtomicRecordStateMap.RecordMetadata remove(
                    String saeId, String clientHash1, String clientHash2)
                    throws RemoteException, NotBoundException {
                return rmiManager.connectBySaeId(saeId).removeRecord(clientHash1, clientHash2);
            }
        };
    }
}
