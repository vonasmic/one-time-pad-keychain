package fel.cvut.node.interNodeCommunication;

import fel.cvut.node.Address;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.NodeRef;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.KeyItem;
import fel.cvut.qkd.KeyItems;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;

import java.rmi.AccessException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Default {@link NodeCommands} implementation exposed over RMI.
 *
 * <p>Authorization (F-01): the caller is the SAE ID bound by {@link RmiCallerContext} from the
 * peer's pinned TLS leaf, never a call argument. Calls without an authenticated caller are refused.
 * <ul>
 *   <li>{@code synchronize}, {@code lockFetch}, {@code insert}: the {@code issuingSaeId} argument
 *       (and for {@code synchronize} the header's {@code saeId}) must equal the caller.</li>
 *   <li>{@code removeRecord}, {@code markOriginProvisioned}: the caller must be a party of the
 *       stored row (its counterpart {@code saeId} or its {@code issuingSaeId}).</li>
 *   <li>{@code deleteShare}: a party may delete in any state. A non-party (re-provision handover:
 *       the device moved to the caller's SAE) may delete only a completed share
 *       ({@code RECORD_SHARED} / {@code ORIGIN_PROVISIONED}); this is logged.</li>
 * </ul>
 */
public class NodeCommandsService implements fel.cvut.node.NodeCommands {

    private static final Logger LOG = Logger.getLogger(NodeCommandsService.class.getName());

    private final NodeRef selfRef;
    private final AtomicRecordStateMap atomicRecordStateMap;
    private final SharedKeyMaterialStore sharedKeyMaterialStore;
    private final Qkd014Client qkdClient;
    private final RmiManager rmiManager;

    public NodeCommandsService(
            NodeRef selfRef,
            AtomicRecordStateMap atomicRecordStateMap,
            Qkd014Client qkdClient,
            SharedKeyMaterialStore sharedKeyMaterialStore
    ) {
        this(selfRef, atomicRecordStateMap, qkdClient, sharedKeyMaterialStore, new RmiManager(selfRef.getAddress()));
    }

    public NodeCommandsService(
            NodeRef selfRef,
            AtomicRecordStateMap atomicRecordStateMap,
            Qkd014Client qkdClient,
            SharedKeyMaterialStore sharedKeyMaterialStore,
            RmiManager rmiManager
    ) {
        this.selfRef = Objects.requireNonNull(selfRef, "selfRef must not be null");
        this.atomicRecordStateMap = Objects.requireNonNull(atomicRecordStateMap, "atomicRecordStateMap must not be null");
        this.qkdClient = Objects.requireNonNull(qkdClient, "qkdClient must not be null");
        this.sharedKeyMaterialStore = Objects.requireNonNull(
                sharedKeyMaterialStore,
                "sharedKeyMaterialStore must not be null"
        );
        this.rmiManager = Objects.requireNonNull(rmiManager, "rmiManager must not be null");
    }

    @Override
    public String ping(Address from) throws RemoteException {
        return "pong from " + selfRef;
    }

    @Override
    public AtomicRecordStateMap.RecordMetadata getRecordMetadata(String clientHash1, String clientHash2)
            throws RemoteException {
        requireCaller();
        return atomicRecordStateMap.get(clientHash1, clientHash2).orElse(null);
    }

    @Override
    public AtomicRecordStateMap.SynchronizeOutcome synchronize(
            ClientRecord.ClientHeader clientHeader, String issuingSaeId) throws RemoteException {
        Objects.requireNonNull(clientHeader, "clientHeader must not be null");
        String caller = requireCallerIs(issuingSaeId, "synchronize");
        if (!caller.equals(clientHeader.saeId())) {
            throw new AccessException("synchronize: header saeId must be the calling SAE " + caller);
        }
        return atomicRecordStateMap.synchronize(clientHeader, caller);
    }

    @Override
    public boolean markOriginProvisioned(String clientHash1, String clientHash2) throws RemoteException {
        Optional<AtomicRecordStateMap.RecordMetadata> current = atomicRecordStateMap.get(clientHash1, clientHash2);
        if (current.isEmpty()) {
            requireCaller();
            return false;
        }
        requireParty(current.get(), "markOriginProvisioned");
        return atomicRecordStateMap.markOriginProvisioned(clientHash1, clientHash2);
    }

    @Override
    public boolean lockFetch(String clientHash1, String clientHash2, String issuingSaeId) throws RemoteException {
        String caller = requireCallerIs(issuingSaeId, "lockFetch");
        return atomicRecordStateMap.lockFetch(clientHash1, clientHash2, caller);
    }

    @Override
    public boolean insert(ClientRecord clientRecord, String claimedIssuingSaeId) throws RemoteException {
        Objects.requireNonNull(clientRecord, "clientRecord must not be null");
        String issuingSaeId = requireCallerIs(claimedIssuingSaeId, "insert");
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
                        == AtomicRecordStateMap.RecordAvailability.RECORD_SHARED
                        || current.get().recordAvailability()
                        == AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED)) {
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
        Optional<AtomicRecordStateMap.RecordMetadata> current = atomicRecordStateMap.get(clientHash1, clientHash2);
        if (current.isEmpty()) {
            requireCaller();
            return null;
        }
        String caller = requireParty(current.get(), "removeRecord");
        logDeleteAttempt(
                clientHash1,
                clientHash2,
                "removed via RMI on SAE " + selfRef.getNodeId() + " by party " + caller
        );
        return atomicRecordStateMap.forceDelete(clientHash1, clientHash2).orElse(null);
    }

    /**
     * Removes the counterpart on the SAE stored in this node's row first, then force-deletes
     * this node's row. If the remote call fails, the local row is kept and the failure propagates.
     */
    @Override
    public void deleteShare(String clientHash1, String clientHash2) throws RemoteException, NotBoundException {
        String caller = requireCaller();
        Optional<AtomicRecordStateMap.RecordMetadata> current = atomicRecordStateMap.get(clientHash1, clientHash2);
        if (current.isEmpty()) {
            return;
        }
        AtomicRecordStateMap.RecordMetadata metadata = current.get();
        if (!isParty(caller, metadata)) {
            AtomicRecordStateMap.RecordAvailability state = metadata.recordAvailability();
            if (state != AtomicRecordStateMap.RecordAvailability.RECORD_SHARED
                    && state != AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED) {
                throw new AccessException("deleteShare: SAE " + caller
                        + " is not a party and the share is not complete (" + state + ")");
            }
            LOG.warning("Handover deletion of completed share " + clientHash1 + " / " + clientHash2
                    + " requested by non-party SAE " + caller);
        }
        logDeleteAttempt(clientHash1, clientHash2, "user confirmed deletion of shared record (caller " + caller + ")");
        if (!Objects.equals(metadata.saeId(), selfRef.getNodeId())) {
            NodeCommands peer = rmiManager.connectBySaeId(metadata.saeId());
            peer.removeRecord(clientHash2, clientHash1);
        }
        atomicRecordStateMap.forceDelete(clientHash1, clientHash2);
    }

    private String requireCaller() throws AccessException {
        return RmiCallerContext.currentSaeId().orElseThrow(
                () -> new AccessException("RMI call without an authenticated (pinned) SAE caller"));
    }

    /** Caller must equal the SAE ID the arguments claim for it. */
    private String requireCallerIs(String claimedSaeId, String operation) throws AccessException {
        String caller = requireCaller();
        if (!caller.equals(claimedSaeId)) {
            throw new AccessException(operation + ": issuingSaeId '" + claimedSaeId
                    + "' does not match the calling SAE " + caller);
        }
        return caller;
    }

    private String requireParty(AtomicRecordStateMap.RecordMetadata metadata, String operation)
            throws AccessException {
        String caller = requireCaller();
        if (!isParty(caller, metadata)) {
            throw new AccessException(operation + ": SAE " + caller + " is not a party of this record");
        }
        return caller;
    }

    private boolean isParty(String caller, AtomicRecordStateMap.RecordMetadata metadata) {
        return caller.equals(selfRef.getNodeId())
                || caller.equals(metadata.saeId())
                || caller.equals(metadata.issuingSaeId());
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
