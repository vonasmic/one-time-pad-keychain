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

    boolean insert(ClientRecord clientRecord, String issuingSaeId) throws RemoteException;

    AtomicRecordStateMap.RecordMetadata removeRecord(String clientHash1, String clientHash2) throws RemoteException;
}
