package fel.cvut.node.interNodeCommunication;

import fel.cvut.node.Address;
import fel.cvut.node.NodeRef;
import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.KeyItem;
import fel.cvut.qkd.KeyItems;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;

import java.rmi.AccessException;
import java.rmi.RemoteException;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Default {@link fel.cvut.node.NodeCommands} implementation exposed over RMI.
 *
 * <p>Authorization (F-01): the caller is the SAE ID bound by {@link RmiCallerContext} from the
 * peer's pinned TLS leaf, never a call argument. Calls without an authenticated caller are
 * refused. Leases are taken in the caller's name; {@code insert} and {@code deleteRecord} run
 * only under a live lease the caller took with the given token, and {@code insert} stores the
 * caller as the issuer and counterpart of the row.
 */
public class NodeCommandsService implements fel.cvut.node.NodeCommands {

    private static final Logger LOG = Logger.getLogger(NodeCommandsService.class.getName());

    private final NodeRef selfRef;
    private final AtomicRecordStateMap atomicRecordStateMap;
    private final SharedKeyMaterialStore sharedKeyMaterialStore;
    private final Qkd014Client qkdClient;
    private final PairLockRegistry registry;

    public NodeCommandsService(
            NodeRef selfRef,
            AtomicRecordStateMap atomicRecordStateMap,
            Qkd014Client qkdClient,
            SharedKeyMaterialStore sharedKeyMaterialStore
    ) {
        this.selfRef = Objects.requireNonNull(selfRef, "selfRef must not be null");
        this.atomicRecordStateMap = Objects.requireNonNull(atomicRecordStateMap, "atomicRecordStateMap must not be null");
        this.qkdClient = Objects.requireNonNull(qkdClient, "qkdClient must not be null");
        this.sharedKeyMaterialStore = Objects.requireNonNull(
                sharedKeyMaterialStore,
                "sharedKeyMaterialStore must not be null"
        );
        this.registry = atomicRecordStateMap.registry();
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
    public boolean lockPair(String clientHash1, String clientHash2, String token) throws RemoteException {
        String caller = requireCaller();
        boolean locked = registry.tryAcquire(PairKey.of(clientHash1, clientHash2), caller, token);
        if (!locked) {
            LOG.info("Pair lock for " + clientHash1 + " / " + clientHash2 + " refused to SAE " + caller
                    + " on SAE " + selfRef.getNodeId() + ": held by another operation");
        }
        return locked;
    }

    @Override
    public boolean renewPair(String clientHash1, String clientHash2, String token) throws RemoteException {
        String caller = requireCaller();
        PairKey pair = PairKey.of(clientHash1, clientHash2);
        // Only the issuer may renew its lease (row tokens are readable by any SAE).
        return holdsAsCaller(pair, caller, token) && registry.renew(pair, token);
    }

    @Override
    public boolean releasePair(String clientHash1, String clientHash2, String token) throws RemoteException {
        String caller = requireCaller();
        PairKey pair = PairKey.of(clientHash1, clientHash2);
        // Only the issuer may release its lease (row tokens are readable by any SAE).
        return holdsAsCaller(pair, caller, token) && registry.release(pair, token);
    }

    /**
     * Checks the lease first (so a stale attempt does not consume KME keys), resolves the key
     * IDs at the KME outside the lease, then stores row and material in one lease transaction.
     */
    @Override
    public void insert(ClientRecord clientRecord, String token) throws RemoteException, PairLockLostException {
        Objects.requireNonNull(clientRecord, "clientRecord must not be null");
        String caller = requireCaller();
        ClientRecord.ClientHeader header = clientRecord.getClientHeader();
        if (!caller.equals(header.saeId())) {
            throw new AccessException("insert: header saeId must be the calling SAE " + caller);
        }
        PairKey pair = PairKey.of(header.clientHash1(), header.clientHash2());
        if (!holdsAsCaller(pair, caller, token)) {
            LOG.warning("Refused key material for hashes " + header.clientHash1() + " / "
                    + header.clientHash2() + " from SAE " + caller + " on SAE " + selfRef.getNodeId()
                    + ": the caller does not hold the pair lease with this token");
            throw new PairLockLostException("SAE " + selfRef.getNodeId()
                    + " does not hold a pair lease of SAE " + caller + " with this token.");
        }
        List<String> keyMaterial;
        try {
            KeyContainer keyContainer = qkdClient.getKeyWithKeyIds(caller, clientRecord.getPayload());
            List<KeyItem> keys = KeyItems.extractKeys(keyContainer);
            keyMaterial = KeyItems.extractKeyMaterial(keys);
        } catch (Qkd014ClientException ex) {
            throw new RemoteException("Target record insert failed while resolving key IDs.", ex);
        } catch (RuntimeException ex) {
            throw new RemoteException("Target record insert failed while resolving key IDs.", ex);
        }
        try {
            sharedKeyMaterialStore.writeKeysAvailable(clientRecord.withPayload(keyMaterial), caller, token);
        } catch (PairLockLostException ex) {
            LOG.warning("Refused key material for hashes " + header.clientHash1() + " / "
                    + header.clientHash2() + " from SAE " + caller + " on SAE " + selfRef.getNodeId()
                    + ": the lease was lost while the keys were resolved");
            throw ex;
        } catch (Exception ex) {
            throw new RemoteException("Target record insert failed.", ex);
        }
    }

    @Override
    public AtomicRecordStateMap.DeleteOutcome deleteRecord(
            String clientHash1, String clientHash2, String leaseToken, String rowToken)
            throws RemoteException, PairLockLostException {
        String caller = requireCaller();
        LOG.info("Attempting to delete record for hashes " + clientHash1 + " / " + clientHash2
                + " on SAE " + selfRef.getNodeId() + " for SAE " + caller);
        AtomicRecordStateMap.DeleteOutcome outcome =
                atomicRecordStateMap.deleteIfToken(caller, leaseToken, clientHash1, clientHash2, rowToken);
        if (outcome == AtomicRecordStateMap.DeleteOutcome.TOKEN_MISMATCH) {
            LOG.warning("Delete of " + clientHash1 + " / " + clientHash2 + " by SAE " + caller
                    + " refused on SAE " + selfRef.getNodeId() + ": the row carries another token");
        }
        return outcome;
    }

    private boolean holdsAsCaller(PairKey pair, String caller, String token) {
        return registry.lease(pair)
                .filter(lease -> lease.token().equals(token) && lease.issuerSaeId().equals(caller))
                .isPresent();
    }

    private String requireCaller() throws AccessException {
        return RmiCallerContext.currentSaeId().orElseThrow(
                () -> new AccessException("RMI call without an authenticated (pinned) SAE caller"));
    }
}
