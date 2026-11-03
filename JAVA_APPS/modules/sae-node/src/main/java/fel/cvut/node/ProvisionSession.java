package fel.cvut.node;

import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.pairlock.PairBusyException;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairOperation;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.qkd.Qkd014ClientException;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeKemFill;
import fel.cvut.se.SeSessionUplink;
import fel.cvut.terminal.ClientSelector;

import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Insert / reuse / reselect FSM for one provision uplink. {@link Node} owns accept and TLS I/O.
 *
 * <p>Every change of a share runs while the operation holds the pair lock on both SAEs of the
 * share ({@link Locks}, lower SAE ID first, refused at once when busy). Operator prompts are
 * shown without holding a lock. A {@link Outcome.Generated} or {@link Outcome.Existing} hands the
 * held locks to the caller as a {@link Delivery}: the caller transfers the payload to the
 * device, calls {@link Delivery#afterDeviceAck()} (origin row and gap guard) before it reports
 * the share complete, and closes the delivery (releases both locks, remote first). A new share
 * is stored on the peer SAE before its payload is handed out.
 */
public final class ProvisionSession {

    private static final Logger LOG = Logger.getLogger(ProvisionSession.class.getName());

    public sealed interface Outcome {
        record Generated(byte[] payload, Delivery delivery) implements Outcome {
        }

        record Existing(byte[] payload, Delivery delivery) implements Outcome {
        }

        record Reselect() implements Outcome {
        }

        record InProgress(String operatorMessage) implements Outcome {
        }
    }

    public static final String LOCK_BUSY_MESSAGE = PairBusyException.BUSY_MESSAGE;
    public static final String PEER_INSERT_FAILED_MESSAGE =
            "The peer SAE could not store the new keys. No keys were sent to the device.";
    public static final String SHARE_CHANGED_MESSAGE =
            "The shared keys changed while you were deciding. Nothing was deleted; check them again.";
    public static final String UNREACHABLE_MESSAGE =
            "The SAE holding the other half of this share is unreachable. Keys were not sent to the device.";
    public static final String ORPHAN_DELETED_MESSAGE =
            "The other SAE no longer holds this share. The stored keys were deleted and not sent. "
                    + "Provision both devices again.";
    public static final String OWN_ISSUED_MESSAGE =
            "Those keys were generated on this SAE and are already on the device that created them. "
                    + "No keys were sent to the device.";
    public static final String PAYLOAD_MISSING_MESSAGE =
            "Shared keys were found but the stored payload is missing. Retry.";

    /** Rows of this SAE, in this SAE's orientation. */
    public interface Records {
        Optional<AtomicRecordStateMap.RecordMetadata> get(String clientHash1, String clientHash2);

        Optional<List<String>> readPayload(String clientHash1, String clientHash2) throws IOException;
    }

    /**
     * Rows of any SAE (this one included) in the orientation stored on that SAE; the callers
     * reverse the hashes for the other SAE of a share.
     */
    public interface RemoteRecords {
        AtomicRecordStateMap.RecordMetadata get(String saeId, String clientHash1, String clientHash2)
                throws RemoteException, NotBoundException;

        /** Compare-and-delete on {@code saeId} under the operation's lease {@code leaseToken}. */
        AtomicRecordStateMap.DeleteOutcome delete(
                String saeId, String clientHash1, String clientHash2, String leaseToken, String rowToken)
                throws RemoteException, NotBoundException, PairLockLostException;
    }

    /** Pair locks on two SAEs, lower SAE ID first. */
    @FunctionalInterface
    public interface Locks {
        PairOperation acquire(String saeA, String saeB, String clientHash1, String clientHash2)
                throws PairBusyException, RemoteException, NotBoundException;
    }

    /** Origin side of a new share, run under both pair locks. */
    public interface Exchange {
        /** Fetches the keys from the KME. */
        Prepared prepare(ClientRecord clientRecord, SeSessionUplink uplink)
                throws Qkd014ClientException, IOException;

        /**
         * Before the device transfer: the peer SAE resolves the key IDs at its own KME and writes
         * its row {@code KEYS_AVAILABLE} with {@code token} (RMI, fenced by the peer lease).
         */
        void insertPeer(ClientRecord completedRecord, String token)
                throws RemoteException, NotBoundException, PairLockLostException;

        /** After the origin device acknowledged: the origin row {@code KEYS_AVAILABLE} with {@code token}. */
        void writeOrigin(ClientRecord completedRecord, String token) throws PairLockLostException;

        /** Best effort: deletes the peer row written with {@code token} (compare-and-delete under the lease). */
        void removePeer(ClientRecord completedRecord, String token);

        record Prepared(List<String> keyMaterial, List<String> keyIds) {
            public Prepared {
                keyMaterial = List.copyOf(keyMaterial);
                keyIds = List.copyOf(keyIds);
            }
        }
    }

    public interface Operator {
        boolean confirm(String message) throws IOException;

        void notify(String message);
    }

    /** Work to run after the device acknowledged, under the held locks. */
    @FunctionalInterface
    public interface AfterAck {
        void run() throws RemoteException, NotBoundException, PairLockLostException;
    }

    /**
     * Both pair locks of a payload on its way to the device. The holder must close it. Closing
     * before {@link #afterDeviceAck()} succeeded runs the rollback (new share: the peer row is
     * deleted by token) and then releases the locks.
     */
    public static final class Delivery implements AutoCloseable {
        private final PairOperation operation;
        private final AfterAck commit;
        private final Runnable rollback;
        private boolean completed;

        public Delivery(PairOperation operation, AfterAck commit, Runnable rollback) {
            this.operation = Objects.requireNonNull(operation, "operation");
            this.commit = commit;
            this.rollback = rollback;
        }

        public PairOperation operation() {
            return operation;
        }

        /**
         * Gap guard after the device transfer, the origin row (new share), and the gap guard
         * again before the share may be reported complete. Throws when any step fails; the share
         * must then not be reported complete.
         */
        public void afterDeviceAck() throws RemoteException, NotBoundException, PairLockLostException {
            operation.checkpoint();
            if (commit != null) {
                commit.run();
                operation.checkpoint();
            }
            completed = true;
        }

        /** Rolls back an incomplete delivery, then stops renewing and releases both locks (remote first). */
        @Override
        public void close() {
            try {
                if (!completed && rollback != null) {
                    rollback.run();
                }
            } finally {
                operation.close();
            }
        }
    }

    private enum DeleteStep { DELETED, CHANGED, BUSY }

    private final String localSaeId;
    private final Records records;
    private final Exchange exchange;
    private final Operator operator;
    private final RemoteRecords remote;
    private final Locks locks;
    private final SeKemFill kemFill;
    private final List<RmiManager.SaeNode> saeNodes;

    /** @param saeNodes SAE IDs and locations from the SAE directory, for operator prompts */
    public ProvisionSession(
            String localSaeId,
            Records records,
            Exchange exchange,
            Operator operator,
            RemoteRecords remote,
            Locks locks,
            SeKemFill kemFill,
            List<RmiManager.SaeNode> saeNodes
    ) {
        this.localSaeId = Objects.requireNonNull(localSaeId, "localSaeId");
        this.records = Objects.requireNonNull(records, "records");
        this.exchange = Objects.requireNonNull(exchange, "exchange");
        this.operator = Objects.requireNonNull(operator, "operator");
        this.remote = Objects.requireNonNull(remote, "remote");
        this.locks = Objects.requireNonNull(locks, "locks");
        this.kemFill = Objects.requireNonNull(kemFill, "kemFill");
        this.saeNodes = List.copyOf(Objects.requireNonNull(saeNodes, "saeNodes"));
    }

    public Outcome process(ClientRecord clientRecord, SeSessionUplink uplink)
            throws RemoteException, Qkd014ClientException, IOException, NotBoundException, PairLockLostException {
        ClientRecord.ClientHeader header = clientRecord.getClientHeader();
        String clientHash1 = header.clientHash1();
        String clientHash2 = header.clientHash2();
        boolean skipGeneratePrompt = false;
        while (true) {
            Optional<AtomicRecordStateMap.RecordMetadata> local = records.get(clientHash1, clientHash2);
            if (local.isEmpty()) {
                if (!skipGeneratePrompt && !operator.confirm(
                        "No shared keys were found for this pair.\nGenerate new keys now?")) {
                    return new Outcome.Reselect();
                }
                Outcome generated = newShare(clientRecord, uplink);
                if (generated == null) {
                    skipGeneratePrompt = true;
                    continue;
                }
                if (generated == RESTART_WITH_PROMPT) {
                    skipGeneratePrompt = false;
                    continue;
                }
                return generated;
            }
            AtomicRecordStateMap.RecordMetadata metadata = local.get();
            DeleteStep deleted;
            if (!Objects.equals(metadata.saeId(), header.saeId())) {
                if (operator.confirm(existingSharePrompt(metadata, "Did you mean to use those keys?"))) {
                    return deliverExistingShare(header, metadata, uplink);
                }
                if (!operator.confirm(existingSharePrompt(metadata,
                        "This will permanently delete those keys. Do you really want to delete them and generate new ones?"))) {
                    return keepExistingShare();
                }
                deleted = operatorDelete(localSaeId, clientHash1, clientHash2, metadata);
            } else if (Objects.equals(metadata.issuingSaeId(), localSaeId)) {
                if (!operator.confirm(existingSharePrompt(metadata, "Delete them and generate new keys?"))) {
                    return keepExistingShare();
                }
                deleted = operatorDelete(localSaeId, clientHash1, clientHash2, metadata);
            } else {
                return deliverExistingShare(header, metadata, uplink);
            }
            switch (deleted) {
                case BUSY -> {
                    return busy();
                }
                case CHANGED -> {
                    operator.notify(SHARE_CHANGED_MESSAGE);
                    skipGeneratePrompt = false;
                }
                case DELETED -> skipGeneratePrompt = true;
            }
        }
    }

    /** Sentinel: the pair changed before the locks were taken; ask the operator again. */
    private static final Outcome RESTART_WITH_PROMPT = new Outcome.InProgress("restart");

    /**
     * New share under both locks. {@code null}: a share of the target was deleted, start over
     * without asking again; {@link #RESTART_WITH_PROMPT}: a row appeared, start over.
     */
    private Outcome newShare(ClientRecord clientRecord, SeSessionUplink uplink)
            throws RemoteException, Qkd014ClientException, IOException, NotBoundException, PairLockLostException {
        ClientRecord.ClientHeader header = clientRecord.getClientHeader();
        String target = header.saeId();
        String clientHash1 = header.clientHash1();
        String clientHash2 = header.clientHash2();
        PairOperation operation;
        try {
            operation = locks.acquire(localSaeId, target, clientHash1, clientHash2);
        } catch (PairBusyException ex) {
            return busy();
        }
        boolean handedOff = false;
        try {
            if (records.get(clientHash1, clientHash2).isPresent()) {
                return RESTART_WITH_PROMPT;
            }
            AtomicRecordStateMap.RecordMetadata targetRow = remote.get(target, clientHash2, clientHash1);
            if (targetRow != null && !localSaeId.equals(targetRow.saeId())) {
                // The target shares this pair with another SAE: ask without holding the locks.
                operation.close();
                if (!operator.confirm(existingSharePrompt(targetRow,
                        "This will permanently delete those keys. Do you really want to delete them and generate new ones?"))) {
                    return keepExistingShare();
                }
                return switch (operatorDelete(target, clientHash2, clientHash1, targetRow)) {
                    case BUSY -> busy();
                    case CHANGED -> {
                        operator.notify(SHARE_CHANGED_MESSAGE);
                        yield RESTART_WITH_PROMPT;
                    }
                    case DELETED -> null;
                };
            }
            // A target row naming this SAE is a leftover of an earlier attempt: the insert of
            // this operation overwrites it under both locks.
            operator.notify("Generating new keys.");
            Exchange.Prepared prepared = exchange.prepare(clientRecord, uplink);
            operation.checkpoint();
            ClientRecord completed = clientRecord.withPayload(prepared.keyIds());
            String token = operation.token();
            try {
                exchange.insertPeer(completed, token);
                operation.checkpoint();
            } catch (RemoteException | NotBoundException | PairLockLostException | RuntimeException ex) {
                LOG.log(Level.WARNING, "SAE " + target + " did not store the new share for hashes "
                        + clientHash1 + " / " + clientHash2 + "; nothing is sent to the device", ex);
                exchange.removePeer(completed, token);
                return inProgress(PEER_INSERT_FAILED_MESSAGE);
            }
            byte[] payload = encodeDownlink(uplink, prepared.keyMaterial(),
                    SeConstants.DECRYPT_HALF_ORIGIN, header.padPlainLen());
            Delivery delivery = new Delivery(operation,
                    () -> exchange.writeOrigin(completed, token),
                    () -> exchange.removePeer(completed, token));
            handedOff = true;
            return new Outcome.Generated(payload, delivery);
        } finally {
            if (!handedOff) {
                operation.close();
            }
        }
    }

    /**
     * Operator delete of a share whose row on {@code rowSae} (hashes as stored there) was shown
     * as {@code shown}. Locks both SAEs, verifies the row still carries the shown token, deletes
     * the counterpart (remote) first and the shown row last, both by token, then releases.
     */
    private DeleteStep operatorDelete(
            String rowSae, String rowHash1, String rowHash2, AtomicRecordStateMap.RecordMetadata shown)
            throws RemoteException, NotBoundException, PairLockLostException {
        String counterpart = shown.saeId();
        PairOperation operation;
        try {
            operation = locks.acquire(rowSae, counterpart, rowHash1, rowHash2);
        } catch (PairBusyException ex) {
            return DeleteStep.BUSY;
        }
        try (operation) {
            AtomicRecordStateMap.RecordMetadata current = remote.get(rowSae, rowHash1, rowHash2);
            if (current == null || !current.token().equals(shown.token())) {
                LOG.info("Operator delete of " + rowHash1 + " / " + rowHash2 + " on SAE " + rowSae
                        + " refused: the row changed after it was shown");
                return DeleteStep.CHANGED;
            }
            AtomicRecordStateMap.DeleteOutcome counterpartOutcome =
                    remote.delete(counterpart, rowHash2, rowHash1, operation.token(), shown.token());
            if (counterpartOutcome != AtomicRecordStateMap.DeleteOutcome.DELETED) {
                LOG.info("Operator delete: counterpart row on SAE " + counterpart + " was " + counterpartOutcome);
            }
            AtomicRecordStateMap.DeleteOutcome rowOutcome =
                    remote.delete(rowSae, rowHash1, rowHash2, operation.token(), shown.token());
            LOG.info("Operator delete of " + rowHash1 + " / " + rowHash2 + " on SAE " + rowSae + ": " + rowOutcome);
            return rowOutcome == AtomicRecordStateMap.DeleteOutcome.TOKEN_MISMATCH
                    ? DeleteStep.CHANGED
                    : DeleteStep.DELETED;
        }
    }

    /**
     * Peer side: the stored half is delivered only when both SAEs hold the share with the same
     * token. Checked and consumed under both locks; both rows are deleted (remote first) before
     * the payload is handed to the device.
     */
    private Outcome deliverExistingShare(
            ClientRecord.ClientHeader clientHeader,
            AtomicRecordStateMap.RecordMetadata metadata,
            SeSessionUplink uplink
    ) throws IOException, RemoteException, NotBoundException, PairLockLostException {
        if (Objects.equals(metadata.issuingSaeId(), localSaeId)) {
            return inProgress(OWN_ISSUED_MESSAGE);
        }
        if (uplink.plainMax() < metadata.padPlainLen()) {
            return inProgress(smallerChipMessage(metadata.padPlainLen(), uplink.plainMax()));
        }
        String clientHash1 = clientHeader.clientHash1();
        String clientHash2 = clientHeader.clientHash2();
        String counterpart = metadata.saeId();
        PairOperation operation;
        try {
            operation = locks.acquire(localSaeId, counterpart, clientHash1, clientHash2);
        } catch (PairBusyException ex) {
            return busy();
        } catch (RemoteException | NotBoundException ex) {
            return inProgress(UNREACHABLE_MESSAGE);
        }
        boolean handedOff = false;
        try {
            Optional<AtomicRecordStateMap.RecordMetadata> local = records.get(clientHash1, clientHash2);
            if (local.isEmpty() || !local.get().token().equals(metadata.token())) {
                return inProgress(SHARE_CHANGED_MESSAGE);
            }
            AtomicRecordStateMap.RecordMetadata other;
            try {
                other = remote.get(counterpart, clientHash2, clientHash1);
            } catch (RemoteException | NotBoundException ex) {
                return inProgress(UNREACHABLE_MESSAGE);
            }
            if (!ShareConsistency.consistent(metadata, other, localSaeId)) {
                LOG.warning("Share " + clientHash1 + " / " + clientHash2 + " is not consistent with SAE "
                        + counterpart + " (" + ShareConsistency.describe(other) + "); deleting the orphan");
                if (other != null && localSaeId.equals(other.saeId())) {
                    remote.delete(counterpart, clientHash2, clientHash1, operation.token(), other.token());
                }
                remote.delete(localSaeId, clientHash1, clientHash2, operation.token(), metadata.token());
                return inProgress(ORPHAN_DELETED_MESSAGE);
            }
            Optional<List<String>> keyMaterial = records.readPayload(clientHash1, clientHash2);
            if (keyMaterial.isEmpty()) {
                return inProgress(PAYLOAD_MISSING_MESSAGE);
            }
            // Consume before send, remote first.
            AtomicRecordStateMap.DeleteOutcome remoteDelete =
                    remote.delete(counterpart, clientHash2, clientHash1, operation.token(), metadata.token());
            if (remoteDelete != AtomicRecordStateMap.DeleteOutcome.DELETED) {
                return inProgress(SHARE_CHANGED_MESSAGE);
            }
            remote.delete(localSaeId, clientHash1, clientHash2, operation.token(), metadata.token());
            operator.notify("Shared keys found. Loading them onto the device.");
            Delivery delivery = new Delivery(operation, null, null);
            handedOff = true;
            return new Outcome.Existing(encodeDownlink(
                    uplink, keyMaterial.get(), SeConstants.DECRYPT_HALF_PEER, metadata.padPlainLen()), delivery);
        } finally {
            if (!handedOff) {
                operation.close();
            }
        }
    }

    private Outcome busy() {
        return inProgress(LOCK_BUSY_MESSAGE);
    }

    private Outcome inProgress(String message) {
        operator.notify(message);
        return new Outcome.InProgress(message);
    }

    private static Outcome keepExistingShare() {
        return new Outcome.InProgress("Existing keys were kept. No keys were sent to the device.");
    }

    private byte[] encodeDownlink(
            SeSessionUplink uplink, List<String> keyMaterial, byte decryptHalf, int padPlain
    ) {
        return kemFill.buildDownlink(uplink, keyMaterial, decryptHalf, padPlain);
    }

    private static String smallerChipMessage(int stored, int chip) {
        return "The shared pads are " + stored + " bytes and this Tropic holds " + chip
                + ". Update the other client's peer pad length and provision again, "
                + "or delete the share and start from this smaller device.";
    }

    private String existingSharePrompt(AtomicRecordStateMap.RecordMetadata metadata, String question) {
        return "Shared keys already exist with SAE "
                + saeDescription(metadata.saeId())
                + " (created "
                + metadata.dateOfCreation()
                + ").\n"
                + question;
    }

    /** Location and id from the SAE directory, matching the SAE selection menu. */
    private String saeDescription(String saeId) {
        String location = saeId;
        for (RmiManager.SaeNode node : saeNodes) {
            if (node.saeId().equals(saeId)) {
                location = node.location();
                break;
            }
        }
        return ClientSelector.formatSaeOptionLabel(new ClientSelector.LabeledOption(saeId, location));
    }
}
