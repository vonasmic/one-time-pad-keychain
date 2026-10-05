package fel.cvut.node;

import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.qkd.Qkd014ClientException;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeKemFill;
import fel.cvut.se.SeSessionUplink;

import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Insert / reuse / reselect FSM for one provision uplink. {@link Node} owns accept and TLS I/O.
 */
public final class ProvisionSession {

    public sealed interface Outcome {
        record Generated(byte[] payload) implements Outcome {
        }

        record Existing(byte[] payload) implements Outcome {
        }

        record Reselect() implements Outcome {
        }

        record InProgress(String operatorMessage) implements Outcome {
        }
    }

    public interface Records {
        AtomicRecordStateMap.SynchronizeOutcome synchronize(
                ClientRecord.ClientHeader header, String localSaeId);

        Optional<AtomicRecordStateMap.RecordMetadata> get(String clientHash1, String clientHash2);

        void tryDelete(String clientHash1, String clientHash2, String issuingSaeId, String reason);

        void forceDeleteLocal(String clientHash1, String clientHash2, String reason);

        Optional<List<String>> readPayload(String clientHash1, String clientHash2) throws IOException;

        void removePayload(String clientHash1, String clientHash2) throws IOException;
    }

    public interface Exchange {
        Optional<List<String>> completeNewExchange(ClientRecord clientRecord, SeSessionUplink uplink)
                throws RemoteException, Qkd014ClientException, IOException, NotBoundException;
    }

    public interface Operator {
        boolean confirm(String message) throws IOException;

        void notify(String message);
    }

    public interface RemoteRecords {
        void forceDelete(String saeId, String clientHash1, String clientHash2)
                throws RemoteException, NotBoundException;
    }

    private final String localSaeId;
    private final Records records;
    private final Exchange exchange;
    private final Operator operator;
    private final RemoteRecords remote;
    private final SeKemFill kemFill;

    public ProvisionSession(
            String localSaeId,
            Records records,
            Exchange exchange,
            Operator operator,
            RemoteRecords remote,
            SeKemFill kemFill
    ) {
        this.localSaeId = Objects.requireNonNull(localSaeId, "localSaeId");
        this.records = Objects.requireNonNull(records, "records");
        this.exchange = Objects.requireNonNull(exchange, "exchange");
        this.operator = Objects.requireNonNull(operator, "operator");
        this.remote = Objects.requireNonNull(remote, "remote");
        this.kemFill = Objects.requireNonNull(kemFill, "kemFill");
    }

    public Outcome process(ClientRecord clientRecord, SeSessionUplink uplink)
            throws RemoteException, Qkd014ClientException, IOException, NotBoundException {
        boolean skipGeneratePrompt = false;
        while (true) {
            ClientRecord.ClientHeader clientHeader = clientRecord.getClientHeader();
            AtomicRecordStateMap.SynchronizeOutcome insertOutcome =
                    records.synchronize(clientHeader, localSaeId);
            switch (insertOutcome) {
                case INSERTED -> {
                    return generateNewShare(clientRecord, uplink, skipGeneratePrompt);
                }
                case RECORD_AVAILABLE, RECORD_SHARED_WITH_DIFFERENT_SAE -> {
                    Outcome existing = resolveExistingShare(clientHeader, uplink, insertOutcome);
                    if (existing == null) {
                        skipGeneratePrompt = true;
                        continue;
                    }
                    return existing;
                }
                case NOT_INSERTED -> {
                    String message =
                            "Record sharing is in progress on another SAE. Wait 10 seconds and then retry.";
                    operator.notify(message);
                    return new Outcome.InProgress(message);
                }
            }
        }
    }

    private Outcome generateNewShare(
            ClientRecord clientRecord, SeSessionUplink uplink, boolean skipGeneratePrompt
    ) throws RemoteException, Qkd014ClientException, IOException, NotBoundException {
        ClientRecord.ClientHeader clientHeader = clientRecord.getClientHeader();
        try {
            if (!skipGeneratePrompt && !operator.confirm(
                    "No shared keys were found for this pair.\nGenerate new keys now?")) {
                records.tryDelete(
                        clientHeader.clientHash1(),
                        clientHeader.clientHash2(),
                        localSaeId,
                        "operator declined to generate new keys");
                return new Outcome.Reselect();
            }
            operator.notify("Generating new keys.");
            Optional<List<String>> keyMaterial = exchange.completeNewExchange(clientRecord, uplink);
            if (keyMaterial.isPresent()) {
                return new Outcome.Generated(encodeDownlink(
                        uplink, keyMaterial.get(), SeConstants.DECRYPT_HALF_ORIGIN));
            }
            return new Outcome.InProgress(
                    "Target SAE rejected the insert. Wait for any provision in progress there to finish and then retry");
        } catch (Qkd014ClientException ex) {
            records.tryDelete(
                    clientHeader.clientHash1(),
                    clientHeader.clientHash2(),
                    localSaeId,
                    "rolled back after QKD key fetch failed");
            throw ex;
        } catch (RemoteException | NotBoundException ex) {
            records.tryDelete(
                    clientHeader.clientHash1(),
                    clientHeader.clientHash2(),
                    localSaeId,
                    "rolled back after target SAE " + clientHeader.saeId()
                            + " was unreachable or rejected the insert");
            throw ex;
        } catch (Exception ex) {
            records.tryDelete(
                    clientHeader.clientHash1(),
                    clientHeader.clientHash2(),
                    localSaeId,
                    "rolled back after key fetch or target orchestration failed");
            throw ex;
        }
    }

    private Outcome resolveExistingShare(
            ClientRecord.ClientHeader clientHeader,
            SeSessionUplink uplink,
            AtomicRecordStateMap.SynchronizeOutcome insertOutcome
    ) throws IOException, RemoteException, NotBoundException {
        Optional<AtomicRecordStateMap.RecordMetadata> existingMetadata =
                records.get(clientHeader.clientHash1(), clientHeader.clientHash2());
        if (existingMetadata.isEmpty()) {
            return new Outcome.InProgress("Shared-key record disappeared before it could be used. Retry.");
        }
        AtomicRecordStateMap.RecordMetadata metadata = existingMetadata.get();
        if (insertOutcome == AtomicRecordStateMap.SynchronizeOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE) {
            if (operator.confirm(existingSharePrompt(metadata, "Did you mean to use those keys?"))) {
                return deliverExistingShare(clientHeader, metadata, uplink);
            }
            if (!operator.confirm(existingSharePrompt(metadata,
                    "This will permanently delete those keys. Do you really want to delete them and generate new ones?"))) {
                return keepExistingShare();
            }
            return deleteShareAndRestart(clientHeader, metadata);
        }
        if (Objects.equals(metadata.issuingSaeId(), localSaeId)) {
            if (!operator.confirm(existingSharePrompt(metadata, "Delete them and generate new keys?"))) {
                return keepExistingShare();
            }
            return deleteShareAndRestart(clientHeader, metadata);
        }
        return deliverExistingShare(clientHeader, metadata, uplink);
    }

    private Outcome deliverExistingShare(
            ClientRecord.ClientHeader clientHeader,
            AtomicRecordStateMap.RecordMetadata metadata,
            SeSessionUplink uplink
    ) throws IOException, RemoteException, NotBoundException {
        String clientHash1 = clientHeader.clientHash1();
        String clientHash2 = clientHeader.clientHash2();
        remote.forceDelete(metadata.issuingSaeId(), clientHash1, clientHash2);
        Optional<List<String>> keyMaterial = records.readPayload(clientHash1, clientHash2);
        records.forceDeleteLocal(clientHash1, clientHash2, "shared payload delivered to requesting SAE");
        if (keyMaterial.isEmpty()) {
            return new Outcome.InProgress("Shared keys were found but the stored payload is missing. Retry.");
        }
        records.removePayload(clientHash1, clientHash2);
        operator.notify("Shared keys found. Downloading them to the device.");
        return new Outcome.Existing(encodeDownlink(uplink, keyMaterial.get(), SeConstants.DECRYPT_HALF_PEER));
    }

    private static Outcome keepExistingShare() {
        return new Outcome.InProgress("Existing keys were kept. No keys were sent to the device.");
    }

    /** {@code null} means delete done — caller restarts insert. */
    private Outcome deleteShareAndRestart(
            ClientRecord.ClientHeader clientHeader,
            AtomicRecordStateMap.RecordMetadata metadata
    ) throws RemoteException, NotBoundException {
        records.forceDeleteLocal(
                clientHeader.clientHash1(),
                clientHeader.clientHash2(),
                "user confirmed deletion of shared record");
        remote.forceDelete(metadata.saeId(), clientHeader.clientHash1(), clientHeader.clientHash2());
        return null;
    }

    private byte[] encodeDownlink(SeSessionUplink uplink, List<String> keyMaterial, byte decryptHalf) {
        return kemFill.buildDownlink(uplink, keyMaterial, decryptHalf);
    }

    private static String existingSharePrompt(AtomicRecordStateMap.RecordMetadata metadata, String question) {
        return "Shared keys already exist with SAE "
                + metadata.saeId()
                + " (created "
                + metadata.dateOfCreation()
                + ").\n"
                + question;
    }
}
