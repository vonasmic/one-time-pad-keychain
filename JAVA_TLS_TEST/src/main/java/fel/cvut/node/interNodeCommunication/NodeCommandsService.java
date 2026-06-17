package fel.cvut.node.interNodeCommunication;

import fel.cvut.node.Address;
import fel.cvut.node.NodeRef;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.StubRecordFileStore;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.KeyItem;
import fel.cvut.qkd.KeyItems;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;

import java.rmi.RemoteException;
import java.util.List;
import java.util.Objects;

/**
 * Default {@link NodeCommands} implementation exposed over RMI.
 */
public class NodeCommandsService implements fel.cvut.node.NodeCommands {

    private final NodeRef selfRef;
    private final AtomicRecordStateMap atomicRecordStateMap;
    private final StubRecordFileStore stubRecordFileStore;
    private final Qkd014Client qkdClient;

    public NodeCommandsService(
            NodeRef selfRef,
            AtomicRecordStateMap atomicRecordStateMap,
            Qkd014Client qkdClient
    ) {
        this.selfRef = Objects.requireNonNull(selfRef, "selfRef must not be null");
        this.atomicRecordStateMap = Objects.requireNonNull(atomicRecordStateMap, "atomicRecordStateMap must not be null");
        this.qkdClient = Objects.requireNonNull(qkdClient, "qkdClient must not be null");
        this.stubRecordFileStore = new StubRecordFileStore();
    }

    @Override
    public String ping(Address from) throws RemoteException {
        return "pong from " + selfRef;
    }

    @Override
    public byte[] relay(byte[] payload) throws RemoteException {
        return payload;
    }

    @Override
    public AtomicRecordStateMap.RecordMetadata getRecordMetadata(String clientHash1, String clientHash2) throws RemoteException {
        return atomicRecordStateMap.get(clientHash1, clientHash2).orElse(null);
    }

    @Override
    public boolean insert(ClientRecord clientRecord, String issuingSaeId) throws RemoteException {
        Objects.requireNonNull(clientRecord, "clientRecord must not be null");
        ClientRecord.ClientHeader header = clientRecord.getClientHeader();
        AtomicRecordStateMap.StartRecordInsertOutcome outcome =
                atomicRecordStateMap.startRecordInsert(header, issuingSaeId);
        if (outcome != AtomicRecordStateMap.StartRecordInsertOutcome.INSERTED) {
            return false;
        }

        try {
            List<String> keyIds = clientRecord.getPayload();
            KeyContainer keyContainer = qkdClient.getKeyWithKeyIds(issuingSaeId, keyIds);
            List<KeyItem> keys = KeyItems.extractKeys(keyContainer);
            List<String> keyMaterial = KeyItems.extractKeyMaterial(keys);
            ClientRecord recordToStore = clientRecord.withPayload(keyMaterial);

            stubRecordFileStore.write(recordToStore);
            boolean finalized = atomicRecordStateMap.finishRecordInsert(
                    header.clientHash1(),
                    header.clientHash2()
            );
            if (!finalized) {
                atomicRecordStateMap.tryDelete(header.clientHash1(), header.clientHash2(), issuingSaeId);
                throw new RemoteException("Target record finalization failed after payload write.");
            }
            return true;
        } catch (Qkd014ClientException ex) {
            atomicRecordStateMap.tryDelete(header.clientHash1(), header.clientHash2(), issuingSaeId);
            throw new RemoteException("Target record insert failed while resolving key IDs.", ex);
        } catch (Exception ex) {
            atomicRecordStateMap.tryDelete(header.clientHash1(), header.clientHash2(), issuingSaeId);
            throw new RemoteException("Target record insert failed.", ex);
        }
    }

    @Override
    public AtomicRecordStateMap.RecordMetadata removeRecord(String clientHash1, String clientHash2) throws RemoteException {
        return atomicRecordStateMap.forceDelete(clientHash1, clientHash2).orElse(null);
    }
}
