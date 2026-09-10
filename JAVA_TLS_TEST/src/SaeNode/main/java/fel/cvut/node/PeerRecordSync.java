package fel.cvut.node;

import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import fel.cvut.qkd.QkdPadMaterialFetcher;
import fel.cvut.se.SeSessionUplink;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Origin-side new-record exchange: QKD fetch, peer {@code insert} with reversed
 * hash order, origin finalize, and compensating deletes so a failed exchange
 * does not leave split-brain metadata.
 */
public final class PeerRecordSync {

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
        this(selfRef, localRecordStateMap, rmiManager, qkdClient, System.out::println);
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

    /**
     * Completes a new exchange after origin has already reserved {@code RECORD_IN_PROGRESS}.
     *
     * @return QKD key material when both sides finalized; empty when the peer rejected the insert
     */
    public Optional<List<String>> completeNewExchange(ClientRecord clientRecord, SeSessionUplink uplink)
            throws RemoteException, Qkd014ClientException, NotBoundException {
        Objects.requireNonNull(clientRecord, "clientRecord must not be null");
        Objects.requireNonNull(uplink, "uplink must not be null");
        String localSaeId = selfRef.getNodeId();
        ClientRecord.ClientHeader clientHeader = clientRecord.getClientHeader();
        try {
            QkdPadMaterialFetcher.FetchedKeys fetched =
                    padMaterialFetcher.fetch(clientHeader.saeId(), uplink);
            ClientRecord completedRecord = clientRecord.withPayload(fetched.keyIds());
            if (orchestrateTargetInsertThenFinalizeOrigin(completedRecord, localSaeId)) {
                return Optional.of(fetched.keyMaterial());
            }
            return Optional.empty();
        } catch (Qkd014ClientException ex) {
            rollbackOrigin(
                    clientHeader,
                    localSaeId,
                    "rolled back after QKD key fetch failed"
            );
            throw ex;
        } catch (RemoteException | NotBoundException | RuntimeException ex) {
            rollbackOrigin(
                    clientHeader,
                    localSaeId,
                    "rolled back after target SAE " + clientHeader.saeId()
                            + " was unreachable or rejected the insert"
            );
            throw ex;
        }
    }

    boolean orchestrateTargetInsertThenFinalizeOrigin(ClientRecord completedRecord, String localSaeId)
            throws RemoteException, NotBoundException {
        ClientRecord.ClientHeader header = completedRecord.getClientHeader();
        ClientRecord targetRecord = completedRecord.withSecondSaeId(localSaeId).withReversedHashes();
        boolean insertInvoked = false;
        try {
            NodeCommands targetNode = rmiManager.connectBySaeId(header.saeId());
            insertInvoked = true;
            boolean targetSucceeded = targetNode.insert(targetRecord, localSaeId);
            if (!targetSucceeded) {
                rollbackOrigin(
                        header,
                        localSaeId,
                        "rolled back after target SAE rejected insert"
                );
                System.out.println("Target SAE rejected record insert for hashes "
                        + header.clientHash1() + " / " + header.clientHash2());
                return false;
            }

            boolean originFinalized = localRecordStateMap.finishRecordInsert(
                    header.clientHash1(),
                    header.clientHash2()
            );
            if (!originFinalized) {
                throw new IllegalStateException(
                        "Target finalized record, but origin failed to finalize local metadata for hashes "
                                + header.clientHash1()
                                + " / "
                                + header.clientHash2()
                );
            }
            return true;
        } catch (RemoteException | NotBoundException | RuntimeException ex) {
            rollbackOrigin(
                    header,
                    localSaeId,
                    "rolled back after target SAE " + header.saeId() + " connection or insert failed"
            );
            if (insertInvoked) {
                tryRemovePeerRecord(header.saeId(), header.clientHash2(), header.clientHash1());
            }
            throw ex;
        }
    }

    private void rollbackOrigin(ClientRecord.ClientHeader header, String issuingSaeId, String reason) {
        localRecordStateMap.tryDelete(header.clientHash1(), header.clientHash2(), issuingSaeId)
                .ifPresent(metadata -> System.out.println(
                        "Deleted local record for hashes "
                                + header.clientHash1()
                                + " / "
                                + header.clientHash2()
                                + ": "
                                + reason
                ));
    }

    private void tryRemovePeerRecord(String saeId, String clientHash1, String clientHash2) {
        try {
            NodeCommands peer = rmiManager.connectBySaeId(saeId);
            AtomicRecordStateMap.RecordMetadata removed = peer.removeRecord(clientHash1, clientHash2);
            if (removed != null) {
                System.out.println(
                        "Deleted remote record on SAE "
                                + saeId
                                + " for hashes "
                                + clientHash1
                                + " / "
                                + clientHash2
                                + " after origin rollback"
                );
            }
        } catch (Exception ex) {
            System.err.println(
                    "Best-effort peer record delete failed for SAE " + saeId
                            + " hashes " + clientHash1 + " / " + clientHash2
                            + ": " + ex.getMessage()
            );
        }
    }
}
