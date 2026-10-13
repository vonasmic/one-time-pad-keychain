package fel.cvut.node.interNodeCommunication;

import fel.cvut.node.Address;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.NodeRef;
import fel.cvut.node.OriginShareAccess;
import fel.cvut.node.OriginShareCheck;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.KeyItem;
import fel.cvut.qkd.KeyItems;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Default {@link NodeCommands} implementation exposed over RMI.
 */
public class NodeCommandsService implements fel.cvut.node.NodeCommands {

    private static final Logger LOG = Logger.getLogger(NodeCommandsService.class.getName());

    private final NodeRef selfRef;
    private final AtomicRecordStateMap atomicRecordStateMap;
    private final SharedKeyMaterialStore sharedKeyMaterialStore;
    private final Qkd014Client qkdClient;
    private final OriginShareAccess originShareAccess;

    public NodeCommandsService(
            NodeRef selfRef,
            AtomicRecordStateMap atomicRecordStateMap,
            Qkd014Client qkdClient,
            SharedKeyMaterialStore sharedKeyMaterialStore
    ) {
        this(selfRef, atomicRecordStateMap, qkdClient, sharedKeyMaterialStore, OriginShareAccess.unreachable());
    }

    public NodeCommandsService(
            NodeRef selfRef,
            AtomicRecordStateMap atomicRecordStateMap,
            Qkd014Client qkdClient,
            SharedKeyMaterialStore sharedKeyMaterialStore,
            OriginShareAccess originShareAccess
    ) {
        this.selfRef = Objects.requireNonNull(selfRef, "selfRef must not be null");
        this.atomicRecordStateMap = Objects.requireNonNull(atomicRecordStateMap, "atomicRecordStateMap must not be null");
        this.qkdClient = Objects.requireNonNull(qkdClient, "qkdClient must not be null");
        this.sharedKeyMaterialStore = Objects.requireNonNull(
                sharedKeyMaterialStore,
                "sharedKeyMaterialStore must not be null"
        );
        this.originShareAccess = Objects.requireNonNull(originShareAccess, "originShareAccess must not be null");
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
    public AtomicRecordStateMap.RecordMetadata getRecordMetadata(String clientHash1, String clientHash2)
            throws RemoteException {
        return atomicRecordStateMap.get(clientHash1, clientHash2).orElse(null);
    }

    @Override
    public boolean synchronize(ClientRecord.ClientHeader clientHeader, String issuingSaeId) throws RemoteException {
        Objects.requireNonNull(clientHeader, "clientHeader must not be null");
        AtomicRecordStateMap.SynchronizeOutcome outcome =
                atomicRecordStateMap.synchronize(clientHeader, issuingSaeId);
        if (outcome == AtomicRecordStateMap.SynchronizeOutcome.INSERTED) {
            return true;
        }
        if (outcome == AtomicRecordStateMap.SynchronizeOutcome.RECORD_AVAILABLE) {
            reconcileLeftoverShare(clientHeader);
        }
        return false;
    }

    /**
     * Peer already has {@code RECORD_AVAILABLE} (or origin has {@code RECORD_PROVISIONED}).
     * Read the issuing SAE and delete leftover material when the origin share is half-failed.
     * A failed origin read leaves the local row; this method never starts a new reservation.
     */
    private void reconcileLeftoverShare(ClientRecord.ClientHeader clientHeader) {
        Optional<AtomicRecordStateMap.RecordMetadata> local =
                atomicRecordStateMap.get(clientHeader.clientHash1(), clientHeader.clientHash2());
        if (local.isEmpty()) {
            return;
        }
        AtomicRecordStateMap.RecordMetadata origin;
        try {
            origin = readOriginRow(local.get(), clientHeader);
        } catch (RemoteException | NotBoundException ex) {
            LOG.warning(
                    "Origin SAE unreachable while reconciling leftover share for hashes "
                            + clientHeader.clientHash1() + " / " + clientHeader.clientHash2()
                            + ": " + ex.getMessage()
            );
            return;
        }
        OriginShareCheck.Decision decision = OriginShareCheck.decide(origin, Instant.now());
        switch (decision) {
            case PROVISIONED, IN_PROGRESS -> {
                // Keep both rows. A new provision must not start.
            }
            case DELETE_LOCAL -> forceDeleteLocal(clientHeader, "origin already reserved a new synchronization");
            case DELETE_BOTH -> {
                forceDeleteLocal(clientHeader, "origin share is missing or stale");
                tryRemoveOrigin(local.get(), clientHeader);
            }
        }
    }

    private AtomicRecordStateMap.RecordMetadata readOriginRow(
            AtomicRecordStateMap.RecordMetadata local,
            ClientRecord.ClientHeader clientHeader
    ) throws RemoteException, NotBoundException {
        if (Objects.equals(local.issuingSaeId(), selfRef.getNodeId())) {
            return local;
        }
        return originShareAccess.get(
                local.issuingSaeId(),
                clientHeader.clientHash2(),
                clientHeader.clientHash1()
        );
    }

    private void forceDeleteLocal(ClientRecord.ClientHeader clientHeader, String reason) {
        logDeleteAttempt(clientHeader.clientHash1(), clientHeader.clientHash2(), reason);
        atomicRecordStateMap.forceDelete(clientHeader.clientHash1(), clientHeader.clientHash2());
    }

    private void tryRemoveOrigin(
            AtomicRecordStateMap.RecordMetadata local,
            ClientRecord.ClientHeader clientHeader
    ) {
        if (Objects.equals(local.issuingSaeId(), selfRef.getNodeId())) {
            return;
        }
        try {
            originShareAccess.remove(
                    local.issuingSaeId(),
                    clientHeader.clientHash2(),
                    clientHeader.clientHash1()
            );
        } catch (RemoteException | NotBoundException ex) {
            LOG.warning(
                    "Best-effort origin record delete failed for SAE " + local.issuingSaeId()
                            + " hashes " + clientHeader.clientHash2() + " / " + clientHeader.clientHash1()
                            + ": " + ex.getMessage()
            );
        }
    }

    @Override
    public boolean lockFetch(String clientHash1, String clientHash2, String issuingSaeId) throws RemoteException {
        return atomicRecordStateMap.lockFetch(clientHash1, clientHash2, issuingSaeId);
    }

    @Override
    public boolean insert(ClientRecord clientRecord, String issuingSaeId) throws RemoteException {
        Objects.requireNonNull(clientRecord, "clientRecord must not be null");
        ClientRecord.ClientHeader header = clientRecord.getClientHeader();
        validateFetchingReservation(header.clientHash1(), header.clientHash2(), issuingSaeId);

        try {
            List<String> keyIds = clientRecord.getPayload();
            KeyContainer keyContainer = qkdClient.getKeyWithKeyIds(issuingSaeId, keyIds);
            List<KeyItem> keys = KeyItems.extractKeys(keyContainer);
            List<String> keyMaterial = KeyItems.extractKeyMaterial(keys);
            ClientRecord recordToStore = clientRecord.withPayload(keyMaterial);

            sharedKeyMaterialStore.write(recordToStore);
            boolean finalized = atomicRecordStateMap.finishRecordInsert(
                    header.clientHash1(),
                    header.clientHash2()
            );
            if (!finalized) {
                var current = atomicRecordStateMap.get(header.clientHash1(), header.clientHash2());
                if (current.isPresent()
                        && (current.get().recordAvailability()
                        == AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE
                        || current.get().recordAvailability()
                        == AtomicRecordStateMap.RecordAvailability.RECORD_PROVISIONED)) {
                    return true;
                }
                logDeleteAttempt(
                        header.clientHash1(),
                        header.clientHash2(),
                        "rolled back after finalization failed on target SAE "
                                + selfRef.getNodeId()
                );
                atomicRecordStateMap.tryDelete(header.clientHash1(), header.clientHash2(), issuingSaeId);
                throw new RemoteException("Target record finalization failed after payload write.");
            }
            return true;
        } catch (Qkd014ClientException ex) {
            logDeleteAttempt(
                    header.clientHash1(),
                    header.clientHash2(),
                    "rolled back after key ID resolution failed on target SAE " + selfRef.getNodeId()
            );
            atomicRecordStateMap.tryDelete(header.clientHash1(), header.clientHash2(), issuingSaeId);
            throw new RemoteException("Target record insert failed while resolving key IDs.", ex);
        } catch (Exception ex) {
            logDeleteAttempt(
                    header.clientHash1(),
                    header.clientHash2(),
                    "rolled back after insert failed on target SAE " + selfRef.getNodeId()
            );
            atomicRecordStateMap.tryDelete(header.clientHash1(), header.clientHash2(), issuingSaeId);
            throw new RemoteException("Target record insert failed.", ex);
        }
    }

    @Override
    public AtomicRecordStateMap.RecordMetadata removeRecord(String clientHash1, String clientHash2)
            throws RemoteException {
        logDeleteAttempt(
                clientHash1,
                clientHash2,
                "removed via RMI on SAE " + selfRef.getNodeId()
        );
        return atomicRecordStateMap.forceDelete(clientHash1, clientHash2).orElse(null);
    }

    private void validateFetchingReservation(String clientHash1, String clientHash2, String issuingSaeId)
            throws RemoteException {
        Optional<AtomicRecordStateMap.RecordMetadata> current =
                atomicRecordStateMap.get(clientHash1, clientHash2);
        if (current.isEmpty()
                || current.get().recordAvailability()
                != AtomicRecordStateMap.RecordAvailability.RECORD_FETCHING_STARTED
                || !Objects.equals(current.get().issuingSaeId(), issuingSaeId)) {
            throw new RemoteException(
                    "Target SAE "
                            + selfRef.getNodeId()
                            + " has no RECORD_FETCHING_STARTED reservation for this issuer."
            );
        }
    }

    private static void logDeleteAttempt(String clientHash1, String clientHash2, String reason) {
        LOG.info(
                "Attempting to delete record for hashes "
                        + clientHash1
                        + " / "
                        + clientHash2
                        + ": "
                        + reason
        );
    }
}
