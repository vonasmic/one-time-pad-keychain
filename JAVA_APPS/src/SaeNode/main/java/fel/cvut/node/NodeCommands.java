package fel.cvut.node;

import fel.cvut.node.Address;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;

import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * Contract for inter-node RMI calls.
 */
public interface NodeCommands extends Remote {
    String ping(Address from) throws RemoteException;

    AtomicRecordStateMap.RecordMetadata getRecordMetadata(String clientHash1, String clientHash2) throws RemoteException;

    /**
     * Reserves {@code RECORD_SYNCHRONIZATION} for the hash pair using the same eligibility
     * rules as a local synchronize.
     *
     * @return the same eligibility outcome as a local synchronize
     */
    AtomicRecordStateMap.SynchronizeOutcome synchronize(
            ClientRecord.ClientHeader clientHeader, String issuingSaeId) throws RemoteException;

    /**
     * Promotes local {@code RECORD_SYNCHRONIZATION} owned by {@code issuingSaeId} to
     * {@code RECORD_FETCHING_STARTED}.
     */
    boolean lockFetch(String clientHash1, String clientHash2, String issuingSaeId) throws RemoteException;

    boolean insert(ClientRecord clientRecord, String issuingSaeId) throws RemoteException;

    AtomicRecordStateMap.RecordMetadata removeRecord(String clientHash1, String clientHash2) throws RemoteException;

    /**
     * Deletes this node's row for the hash pair and the counterpart on {@code metadata.saeId()}.
     */
    void deleteShare(String clientHash1, String clientHash2) throws RemoteException, NotBoundException;

    /**
     * Promotes this node's {@code RECORD_SHARED} row to {@code ORIGIN_PROVISIONED}.
     * The origin calls this on the peer (reversed hashes) and then on itself.
     *
     * @return {@code true} when the row changed
     */
    boolean markOriginProvisioned(String clientHash1, String clientHash2) throws RemoteException;
}
