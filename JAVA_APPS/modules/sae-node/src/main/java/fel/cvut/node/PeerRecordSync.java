package fel.cvut.node;

import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import fel.cvut.qkd.QkdPadMaterialFetcher;
import fel.cvut.se.SeSessionUplink;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Origin side of a new share, run while the operation holds the pair lock on both SAEs:
 * {@link #prepare} fetches the keys from the KME; {@link #insertPeer} writes the peer row over
 * RMI before the device transfer; after the origin device has acknowledged its keys,
 * {@link #writeOrigin} writes the origin row. Both rows are {@code KEYS_AVAILABLE} with the
 * operation token. {@link #removePeer} deletes the peer row again by token when the share is not
 * completed (best effort; a leftover is an orphan the consistency check removes).
 */
public final class PeerRecordSync implements ProvisionSession.Exchange {

    private static final Logger LOG = Logger.getLogger(PeerRecordSync.class.getName());

    private final NodeRef selfRef;
    private final AtomicRecordStateMap localRecordStateMap;
    private final RmiManager rmiManager;
    private final QkdPadMaterialFetcher padMaterialFetcher;

    public PeerRecordSync(
            NodeRef selfRef,
            AtomicRecordStateMap localRecordStateMap,
            RmiManager rmiManager,
            Qkd014Client qkdClient
    ) {
        this(selfRef, localRecordStateMap, rmiManager, qkdClient, LOG::info);
    }

    public PeerRecordSync(
            NodeRef selfRef,
            AtomicRecordStateMap localRecordStateMap,
            RmiManager rmiManager,
            Qkd014Client qkdClient,
            Consumer<String> progressLog
    ) {
        this.selfRef = Objects.requireNonNull(selfRef, "selfRef must not be null");
        this.localRecordStateMap = Objects.requireNonNull(localRecordStateMap, "localRecordStateMap must not be null");
        this.rmiManager = Objects.requireNonNull(rmiManager, "rmiManager must not be null");
        this.padMaterialFetcher = new QkdPadMaterialFetcher(
                Objects.requireNonNull(qkdClient, "qkdClient must not be null"),
                Objects.requireNonNull(progressLog, "progressLog must not be null")
        );
    }

    @Override
    public Prepared prepare(ClientRecord clientRecord, SeSessionUplink uplink) throws Qkd014ClientException {
        Objects.requireNonNull(clientRecord, "clientRecord must not be null");
        Objects.requireNonNull(uplink, "uplink must not be null");
        ClientRecord.ClientHeader header = clientRecord.getClientHeader();
        QkdPadMaterialFetcher.FetchedKeys fetched =
                padMaterialFetcher.fetch(header.saeId(), uplink, header.padPlainLen());
        return new Prepared(fetched.keyMaterial(), fetched.keyIds());
    }

    @Override
    public void insertPeer(ClientRecord completedRecord, String token)
            throws RemoteException, NotBoundException, PairLockLostException {
        ClientRecord targetRecord = peerRecord(completedRecord);
        String peerSaeId = completedRecord.getClientHeader().saeId();
        NodeCommands target = rmiManager.connectBySaeId(peerSaeId);
        try {
            target.insert(targetRecord, token);
        } catch (RemoteException ex) {
            // The reply may be lost after the peer committed: remove its row by token.
            removePeerRowQuietly(target, peerSaeId, targetRecord.getClientHeader(), token);
            throw ex;
        }
    }

    @Override
    public void writeOrigin(ClientRecord completedRecord, String token) throws PairLockLostException {
        Objects.requireNonNull(completedRecord, "completedRecord must not be null");
        localRecordStateMap.writeOrigin(token, completedRecord.getClientHeader());
    }

    @Override
    public void removePeer(ClientRecord completedRecord, String token) {
        ClientRecord.ClientHeader targetHeader = peerRecord(completedRecord).getClientHeader();
        String peerSaeId = completedRecord.getClientHeader().saeId();
        NodeCommands target;
        try {
            target = rmiManager.connectBySaeId(peerSaeId);
        } catch (Exception ex) {
            LOG.warning("Best-effort peer row rollback failed for SAE " + peerSaeId + " hashes "
                    + targetHeader.clientHash1() + " / " + targetHeader.clientHash2() + ": " + ex.getMessage());
            return;
        }
        removePeerRowQuietly(target, peerSaeId, targetHeader, token);
    }

    private ClientRecord peerRecord(ClientRecord completedRecord) {
        Objects.requireNonNull(completedRecord, "completedRecord must not be null");
        return completedRecord.withSecondSaeId(selfRef.getNodeId()).withReversedHashes();
    }

    private static void removePeerRowQuietly(
            NodeCommands target, String saeId, ClientRecord.ClientHeader targetHeader, String token) {
        try {
            AtomicRecordStateMap.DeleteOutcome outcome = target.deleteRecord(
                    targetHeader.clientHash1(), targetHeader.clientHash2(), token, token);
            LOG.info("Rollback of the peer row on SAE " + saeId + " for hashes "
                    + targetHeader.clientHash1() + " / " + targetHeader.clientHash2() + ": " + outcome);
        } catch (Exception ex) {
            LOG.warning("Best-effort peer row rollback failed for SAE " + saeId + " hashes "
                    + targetHeader.clientHash1() + " / " + targetHeader.clientHash2() + ": " + ex.getMessage());
        }
    }
}
