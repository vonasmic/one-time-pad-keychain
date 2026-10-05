package fel.cvut.node;

import fel.cvut.node.Address;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * Contract for inter-node RMI calls.
 */
public interface NodeCommands extends Remote {
    String ping(Address from) throws RemoteException;

    byte[] relay(byte[] payload) throws RemoteException;

    AtomicRecordStateMap.RecordMetadata getRecordMetadata(String clientHash1, String clientHash2) throws RemoteException;

    /**
     * Reserves {@code RECORD_SYNCHRONIZATION} for the hash pair using the same eligibility
     * rules as a local synchronize.
     *
     * @return {@code true} when this peer accepted/created the synchronization reservation
     */
    boolean synchronize(ClientRecord.ClientHeader clientHeader, String issuingSaeId) throws RemoteException;

    /**
     * Promotes local {@code RECORD_SYNCHRONIZATION} owned by {@code issuingSaeId} to
     * {@code RECORD_FETCHING_STARTED}.
     */
    boolean lockFetch(String clientHash1, String clientHash2, String issuingSaeId) throws RemoteException;

    boolean insert(ClientRecord clientRecord, String issuingSaeId) throws RemoteException;

    AtomicRecordStateMap.RecordMetadata removeRecord(String clientHash1, String clientHash2) throws RemoteException;
}
