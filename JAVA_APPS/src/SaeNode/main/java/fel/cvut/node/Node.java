package fel.cvut.node;

import fel.cvut.db.DB;
import fel.cvut.db.DatabaseConfig;
import fel.cvut.db.SqliteLogging;
import fel.cvut.db.RecordRetention;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import fel.cvut.terminal.AppLogging;
import fel.cvut.se.EnvSecrets;
import fel.cvut.se.SeKemFill;
import fel.cvut.se.SeProvisionAck;
import fel.cvut.se.SeSessionBinding;
import fel.cvut.se.SeSessionUplink;
import fel.cvut.terminal.LocalOperatorConsole;
import fel.cvut.tls.HsmNodeTls;
import fel.cvut.tls.SoftwareTls;
import fel.cvut.usb.SeUsbLink;
import fel.cvut.usb.SeUsbTls;
import fel.cvut.utimaco.Pqmi;
import com.zaxxer.hikari.HikariDataSource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.file.Path;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.sql.SQLException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Main node orchestration class.
 *
 * <p>Starts and manages:
 * <ul>
 *   <li>RMI communication for inter-node calls</li>
 *   <li>QKD API access via {@link Qkd014Client}</li>
 *   <li>USB CDC for device {@code PROVISION} (TLS server on the serial stream)</li>
 * </ul>
 */
public class Node implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(Node.class.getName());
    private static final int PROVISION_TRANSFER_TIMEOUT_MS = 900_000;
    /** Short read used only to see whether the wipe line is already waiting. */
    private static final int WIPE_READY_PROBE_MS = 200;
    /**
     * Device already stored the keys, but both rows were not marked
     * {@code ORIGIN_PROVISIONED}. The share stays {@code RECORD_SHARED}.
     */
    public static final String SHARE_NOT_CONSISTENT =
            "Device stored the keys, but the share was not marked provisioned.";
    /** Printed on the line after the 100% bar, once the share is consistent. */
    public static final String SHARE_SUCCESSFUL = "Share successful.";

    private final NodeRef selfRef;
    private final String tlsNodeId;
    private final Qkd014Client qkdClient;
    private final InputHandler inputHandler;
    private final LocalOperatorConsole operatorConsole;
    private final NodeCommands nodeCommands;
    private final AtomicRecordStateMap localRecordStateMap;
    private final SharedKeyMaterialStore sharedKeyMaterialStore;
    private final RmiManager rmiManager;
    private final RecordRetention recordRetention;
    private final PeerRecordSync peerRecordSync;
    private final SeKemFill kemFill;
    private final ExecutorService executor;

    private Pqmi pqmi;
    private SSLContext tlsContext;
    private SSLContext deviceTlsContext;

    private volatile boolean running;

    /**
     * Creates a node instance without starting networking components.
     *
     * @param selfRef                local node reference
     * @param tlsNodeId              TLS identity used for RMI PQC context loading
     * @param qkdClient              QKD client for KME API access
     * @param localRecordStateMap    local record metadata map
     * @param sharedKeyMaterialStore encrypted shared-key material store
     * @param nodeCommands           RMI command implementation
     * @param rmiManager             RMI lifecycle manager
     * @param recordRetention        daily {@code client_record_state} purge
     */
    public Node(
            NodeRef selfRef,
            String tlsNodeId,
            Qkd014Client qkdClient,
            AtomicRecordStateMap localRecordStateMap,
            SharedKeyMaterialStore sharedKeyMaterialStore,
            NodeCommands nodeCommands,
            RmiManager rmiManager,
            RecordRetention recordRetention
    ) {
        this.selfRef = Objects.requireNonNull(selfRef, "selfRef must not be null");
        this.tlsNodeId = Objects.requireNonNull(tlsNodeId, "tlsNodeId must not be null");
        this.qkdClient = Objects.requireNonNull(qkdClient, "qkdClient must not be null");
        this.localRecordStateMap = Objects.requireNonNull(localRecordStateMap, "localRecordStateMap must not be null");
        this.sharedKeyMaterialStore = Objects.requireNonNull(
                sharedKeyMaterialStore,
                "sharedKeyMaterialStore must not be null"
        );
        this.nodeCommands = Objects.requireNonNull(nodeCommands, "nodeCommands must not be null");
        this.rmiManager = Objects.requireNonNull(rmiManager, "rmiManager must not be null");
        this.recordRetention = Objects.requireNonNull(recordRetention, "recordRetention must not be null");
        this.peerRecordSync = new PeerRecordSync(
                selfRef, localRecordStateMap, rmiManager, qkdClient, this::notifyOperator);
        this.kemFill = new SeKemFill();
        this.inputHandler = new InputHandler();
        this.operatorConsole = new LocalOperatorConsole();
        this.executor = Executors.newCachedThreadPool(newDaemonFactory("node-worker"));
    }

    /**
     * Starts RMI first, then the USB provision loop when CDC is enabled.
     * Uses {@link #usePqmi(Pqmi)} if already set (so QKD can share the same {@code Pqmi} config).
     */
    public synchronized void start() {
        if (running) {
            return;
        }

        try {
            if (pqmi == null) {
                pqmi = Pqmi.fromEnvironment();
            }
            tlsContext = HsmNodeTls.createContextForNode(pqmi, tlsNodeId);
            deviceTlsContext = HsmNodeTls.createContextForCommandServer(pqmi, tlsNodeId);

            rmiManager.start(nodeCommands, tlsContext);
            running = true;
            if (usbConfigured()) {
                executor.submit(this::usbLoop);
            } else {
                LOG.info("USB provision disabled (USB_SERIAL_PORT none)");
            }
            recordRetention.start();
        } catch (Exception ex) {
            recordRetention.close();
            closeHsmResources();
            rmiManager.stop();
            running = false;
            throw new IllegalStateException("Failed to start node.", ex);
        }
    }

    /** Shares a {@code Pqmi} config handle (e.g. after QKD client setup). */
    public void usePqmi(Pqmi session) {
        this.pqmi = Objects.requireNonNull(session, "session");
    }

    /**
     * Indicates whether node services are currently running.
     *
     * @return true when started and not yet closed
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * Exposes the QKD client used for KME REST API access.
     *
     * @return configured QKD client
     */
    public Qkd014Client getQkdClient() {
        return qkdClient;
    }

    /**
     * Returns local node reference.
     *
     * @return local node metadata
     */
    public NodeRef getSelfRef() {
        return selfRef;
    }

    /**
     * Returns TLS node identity used by this node.
     *
     * @return TLS node identifier
     */
    public String getTlsNodeId() {
        return tlsNodeId;
    }

    private void usbLoop() {
        UsbTarget target = currentUsbTarget();
        if (target == null) {
            return;
        }
        while (running && !Thread.currentThread().isInterrupted()) {
            try (SeUsbLink usb = SeUsbLink.open(target.serialPort(), target.baudRate())) {
                LOG.info("USB provision on " + usb.serialPortName());
                oneProvisionSession(usb);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception ex) {
                LOG.warning("USB provision session ended: " + explainFailure(ex));
            }
            if (!running) {
                return;
            }
            try {
                if (!operatorConsole.promptYesNo("Provision another device?")) {
                    LOG.info("USB provision stopped");
                    return;
                }
            } catch (Exception e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void oneProvisionSession(SeUsbLink usb) {
        SeSessionBinding.HandshakeExporter exporter = new SeSessionBinding.HandshakeExporter();
        AtomicReference<SSLSocket> attached = new AtomicReference<>();
        boolean[] handshakeDone = {false};
        boolean outcomeReported = false;
        try {
            SeUsbTls.run(
                    usb,
                    deviceTlsContext,
                    "PROVISION",
                    true,
                    ssl -> {
                        ssl.setSoTimeout(100_000);
                        attached.set(ssl);
                        exporter.attach(ssl);
                    },
                    ssl -> {
                        handshakeDone[0] = true;
                        handleProvision(ssl, exporter.require());
                        return null;
                    }
            );
            outcomeReported = true;
        } catch (Exception ex) {
            if (handshakeDone[0] && !outcomeReported) {
                notifyOperator(operatorFailure(ex));
            }
            if (handshakeDone[0]) {
                logSocketFailure(ex);
            } else {
                LOG.warning("TLS command handshake aborted: " + explainFailure(ex));
            }
        } finally {
            exporter.detach(attached.get());
        }
    }

    private void handleProvision(SSLSocket socket, byte[] exporter) throws Exception {
        List<RmiManager.SaeNode> friendlySaeNodes = RmiManager.getKnownSaeNodes().stream()
                .filter(node -> node != null && !Objects.equals(node.saeId(), selfRef.getNodeId()))
                .toList();
        InputHandler.OperatorSelection selection =
                inputHandler.handleInput(socket, exporter, friendlySaeNodes, operatorConsole);
        ProvisionSession.Outcome processResult;
        ProvisionSession session = provisionSession();
        while (true) {
            ClientRecord clientRecord = selection.clientRecord();
            SeSessionUplink uplink = selection.uplink();
            LOG.info("Created client record from LV uplink: " + clientRecord
                    + " (slotSize=" + uplink.slotSize()
                    + ", padCount=" + uplink.padCount()
                    + ", plainMax=" + uplink.plainMax()
                    + ", padPlainLen=" + clientRecord.getClientHeader().padPlainLen() + ")");
            processResult = session.process(clientRecord, uplink);
            if (!(processResult instanceof ProvisionSession.Outcome.Reselect)) {
                break;
            }
            selection = inputHandler.selectForUplink(uplink, friendlySaeNodes, operatorConsole);
        }
        ClientRecord clientRecord = selection.clientRecord();
        byte[] payload = switch (processResult) {
            case ProvisionSession.Outcome.Generated generated -> generated.payload();
            case ProvisionSession.Outcome.Existing existing -> existing.payload();
            default -> null;
        };
        if (payload != null) {
            socket.setSoTimeout(PROVISION_TRANSFER_TIMEOUT_MS);
            waitForDeviceWipe(socket);
            LOG.info("Device Tropic wipe finished, sending LV downlink ("
                    + payload.length + " bytes)");
            notifyOperator("Sending keys to the device…");
            SeProvisionAck.writeTracking(
                    socket.getOutputStream(),
                    socket.getInputStream(),
                    payload,
                    kb -> notifyOperator(SeProvisionAck.downloadProgress(kb, payload.length)));
            SeProvisionAck.read(socket.getInputStream());
            boolean markedProvisioned = true;
            if (processResult instanceof ProvisionSession.Outcome.Generated) {
                ClientRecord.ClientHeader header = clientRecord.getClientHeader();
                markedProvisioned = markOriginProvisionedOnBoth(header);
                if (!markedProvisioned) {
                    LOG.warning(
                            "Device acked provision but both rows were not marked ORIGIN_PROVISIONED for hashes "
                                    + header.clientHash1() + " / " + header.clientHash2()
                    );
                }
            }
            String status = afterDeviceAckStatus(
                    processResult instanceof ProvisionSession.Outcome.Generated,
                    markedProvisioned,
                    payload.length);
            if (markedProvisioned) {
                LOG.info(status);
            } else {
                LOG.warning(status);
            }
            notifyOperator(status);
        } else {
            ClientRecord.ClientHeader header = clientRecord.getClientHeader();
            LOG.info(
                    "No payload sent to TLS client for hashes "
                            + header.clientHash1()
                            + " / "
                            + header.clientHash2()
                            + " and target SAE "
                            + header.saeId()
            );
            String msg = processResult instanceof ProvisionSession.Outcome.InProgress inProgress
                    ? inProgress.operatorMessage()
                    : "No keys were sent to the device.";
            notifyOperator(msg);
        }
    }

    /**
     * Terminal text after the device ack. A new origin share prints the 100% line
     * and {@link #SHARE_SUCCESSFUL} only when {@code markedProvisioned} is true:
     * the peer row and then the origin row are both {@code ORIGIN_PROVISIONED}.
     * Until that return both rows stay {@code RECORD_SHARED}. A stored share
     * prints the same two lines after {@code SE_OK}.
     */
    public static String afterDeviceAckStatus(boolean newOriginShare, boolean markedProvisioned, long payloadLength) {
        if (newOriginShare && !markedProvisioned) {
            return SHARE_NOT_CONSISTENT;
        }
        return SeProvisionAck.downloadComplete(payloadLength) + "\n" + SHARE_SUCCESSFUL;
    }

    /**
     * Keys are already prepared. If the device has not sent {@code TROPIC_WIPE_FINISHED}
     * yet, tell the operator and block until the wipe line arrives.
     */
    private void waitForDeviceWipe(SSLSocket socket) throws IOException {
        socket.setSoTimeout(WIPE_READY_PROBE_MS);
        try {
            SeProvisionAck.awaitWipeFinished(socket.getInputStream());
        } catch (SocketTimeoutException ex) {
            notifyOperator("Waiting for device to finish wipe…");
            socket.setSoTimeout(PROVISION_TRANSFER_TIMEOUT_MS);
            SeProvisionAck.awaitWipeFinished(socket.getInputStream());
        } finally {
            socket.setSoTimeout(PROVISION_TRANSFER_TIMEOUT_MS);
        }
    }

    private void notifyOperator(String message) {
        try {
            operatorConsole.showMessage(message);
        } catch (Exception e) {
            LOG.warning("Failed to send status to operator: " + e.getMessage());
        }
    }

    private ProvisionSession provisionSession() {
        return new ProvisionSession(
                selfRef.getNodeId(),
                new ProvisionSession.Records() {
                    @Override
                    public AtomicRecordStateMap.SynchronizeOutcome synchronize(
                            ClientRecord.ClientHeader header, String localSaeId) {
                        return localRecordStateMap.synchronize(header, localSaeId);
                    }

                    @Override
                    public Optional<AtomicRecordStateMap.RecordMetadata> get(String clientHash1, String clientHash2) {
                        return localRecordStateMap.get(clientHash1, clientHash2);
                    }

                    @Override
                    public void tryDelete(String clientHash1, String clientHash2, String issuingSaeId, String reason) {
                        tryDeleteLocalRecord(clientHash1, clientHash2, issuingSaeId, reason);
                    }

                    @Override
                    public void forceDeleteLocal(String clientHash1, String clientHash2, String reason) {
                        forceDeleteLocalRecord(clientHash1, clientHash2, reason);
                    }

                    @Override
                    public Optional<List<String>> readPayload(String clientHash1, String clientHash2)
                            throws IOException {
                        return sharedKeyMaterialStore.readPayload(clientHash1, clientHash2);
                    }

                    @Override
                    public void removePayload(String clientHash1, String clientHash2) throws IOException {
                        sharedKeyMaterialStore.remove(clientHash1, clientHash2);
                    }
                },
                peerRecordSync::completeNewExchange,
                new ProvisionSession.Operator() {
                    @Override
                    public boolean confirm(String message) throws IOException {
                        return promptOperator(message);
                    }

                    @Override
                    public void notify(String message) {
                        notifyOperator(message);
                    }
                },
                new ProvisionSession.RemoteRecords() {
                    @Override
                    public void forceDelete(String saeId, String clientHash1, String clientHash2)
                            throws RemoteException, NotBoundException {
                        forceDeleteRemoteRecord(saeId, clientHash1, clientHash2);
                    }

                    @Override
                    public void deleteShare(String saeId, String clientHash1, String clientHash2)
                            throws RemoteException, NotBoundException {
                        deleteRemoteShare(saeId, clientHash1, clientHash2);
                    }

                    @Override
                    public AtomicRecordStateMap.RecordMetadata get(
                            String saeId, String clientHash1, String clientHash2)
                            throws RemoteException, NotBoundException {
                        return getRemoteRecord(saeId, clientHash1, clientHash2);
                    }
                },
                kemFill
        );
    }

    private static void logSocketFailure(Exception ex) {
        LOG.log(Level.WARNING, "Socket input handling failed: " + explainFailure(ex), ex);
    }

    private static String operatorFailure(Throwable ex) {
        Qkd014ClientException qkd = findCause(ex, Qkd014ClientException.class);
        if (qkd != null) {
            String detail = qkd.getMessage();
            if (detail != null && !detail.isBlank()) {
                return "QKD failure: " + detail;
            }
            return "QKD failure";
        }
        if (ex instanceof NotBoundException || findCause(ex, NotBoundException.class) != null) {
            return "SAE unreachable";
        }
        if (ex instanceof RemoteException) {
            return "SAE unreachable";
        }
        return "transmission failed";
    }

    private static String explainFailure(Throwable ex) {
        if (ex instanceof Qkd014ClientException) {
            return ex.getMessage();
        }
        if (ex instanceof NotBoundException) {
            return "Target SAE RMI object not found — is the peer node running and registered? ("
                    + ex.getMessage() + ")";
        }
        if (ex instanceof RemoteException) {
            Throwable cause = ex.getCause();
            while (cause != null) {
                if (cause instanceof Qkd014ClientException) {
                    return "Target SAE failed while resolving QKD keys: " + cause.getMessage();
                }
                cause = cause.getCause();
            }
            return "Target SAE RMI call failed: " + ex.getMessage();
        }
        String message = ex.getMessage();
        return message == null || message.isBlank() ? ex.getClass().getSimpleName() : message;
    }

    private static <T extends Throwable> T findCause(Throwable ex, Class<T> type) {
        for (Throwable current = ex; current != null; current = current.getCause()) {
            if (type.isInstance(current)) {
                return type.cast(current);
            }
        }
        return null;
    }

    private boolean promptOperator(String message) throws IOException {
        try {
            return operatorConsole.confirmDeletion(message);
        } catch (Exception e) {
            throw new IOException("Operator confirmation failed", e);
        }
    }

    private void tryDeleteLocalRecord(
            String clientHash1,
            String clientHash2,
            String issuingSaeId,
            String reason
    ) {
        localRecordStateMap.tryDelete(clientHash1, clientHash2, issuingSaeId)
                .ifPresent(metadata -> LOG.info(
                        "Deleted local record for hashes "
                                + clientHash1
                                + " / "
                                + clientHash2
                                + ": "
                                + reason
                ));
    }

    private void forceDeleteLocalRecord(String clientHash1, String clientHash2, String reason) {
        localRecordStateMap.forceDelete(clientHash1, clientHash2)
                .ifPresent(metadata -> LOG.info(
                        "Deleted local record for hashes "
                                + clientHash1
                                + " / "
                                + clientHash2
                                + ": "
                                + reason
                ));
    }

    /**
     * Marks the peer, then the origin. A failed peer mark leaves both rows {@code RECORD_SHARED}.
     */
    private boolean markOriginProvisionedOnBoth(ClientRecord.ClientHeader header) {
        try {
            NodeCommands peer = rmiManager.connectBySaeId(header.saeId());
            if (!peer.markOriginProvisioned(header.clientHash2(), header.clientHash1())) {
                LOG.warning(
                        "Peer SAE " + header.saeId()
                                + " did not accept ORIGIN_PROVISIONED for hashes "
                                + header.clientHash2() + " / " + header.clientHash1()
                );
                return false;
            }
        } catch (RemoteException | NotBoundException ex) {
            LOG.warning(
                    "Peer SAE " + header.saeId()
                            + " was unreachable while marking ORIGIN_PROVISIONED: "
                            + ex.getMessage()
            );
            return false;
        }
        return localRecordStateMap.markOriginProvisioned(header.clientHash1(), header.clientHash2());
    }

    /** Calls {@link NodeCommands#deleteShare} with reversed hashes. */
    private void deleteRemoteShare(String saeId, String clientHash1, String clientHash2)
            throws RemoteException, NotBoundException {
        NodeCommands remoteNode = rmiManager.connectBySaeId(saeId);
        remoteNode.deleteShare(clientHash2, clientHash1);
    }

    private void forceDeleteRemoteRecord(String saeId, String clientHash1, String clientHash2)
            throws RemoteException, NotBoundException {
        NodeCommands remoteNode = rmiManager.connectBySaeId(saeId);
        AtomicRecordStateMap.RecordMetadata removed = remoteNode.removeRecord(clientHash2, clientHash1);
        if (removed != null) {
            LOG.info(
                    "Deleted remote record on SAE "
                            + saeId
                            + " for hashes "
                            + clientHash2
                            + " / "
                            + clientHash1
            );
        }
    }

    private AtomicRecordStateMap.RecordMetadata getRemoteRecord(
            String saeId, String clientHash1, String clientHash2)
            throws RemoteException, NotBoundException {
        if (Objects.equals(saeId, selfRef.getNodeId())) {
            return localRecordStateMap.get(clientHash2, clientHash1).orElse(null);
        }
        NodeCommands remoteNode = rmiManager.connectBySaeId(saeId);
        return remoteNode.getRecordMetadata(clientHash2, clientHash1);
    }

    /**
     * Stops RMI and the USB provision loop, and terminates worker threads.
     **/
    @Override
    public synchronized void close() {
        if (!running) {
            recordRetention.close();
            executor.shutdownNow();
            return;
        }

        running = false;
        rmiManager.stop();
        recordRetention.close();
        executor.shutdownNow();
        closeHsmResources();
    }

    private void closeHsmResources() {
        if (pqmi != null) {
            pqmi.close();
            pqmi = null;
        }
        tlsContext = null;
        deviceTlsContext = null;
    }

    private boolean usbConfigured() {
        return currentUsbTarget() != null;
    }

    private UsbTarget currentUsbTarget() {
        int baudRate = Integer.parseInt(envOrDefault(
                "USB_BAUD_RATE", Integer.toString(SeUsbLink.DEFAULT_BAUD)));
        String serial = envOrDefault("USB_SERIAL_PORT", SeUsbLink.DEFAULT_PORT);
        if (usbDisabled(serial)) {
            return null;
        }
        return new UsbTarget(serial, baudRate);
    }

    private static boolean usbDisabled(String serialPort) {
        String v = serialPort.trim();
        return v.isEmpty()
                || v.equalsIgnoreCase("none")
                || v.equalsIgnoreCase("off")
                || v.equalsIgnoreCase("disabled")
                || v.equals("-");
    }

    private record UsbTarget(String serialPort, int baudRate) {
    }

    /**
     * Entry point.
     *
     * <p>All configuration is read from environment variables (see {@code .env} / {@code env/node-N.env}).
     *
     * <p>Required environment variables:
     * <ul>
     *   <li>{@code SAE_ID}            – local SAE identifier (must match {@code sae-nodes.json})</li>
     *   <li>{@code NODE_RMI_PORT}     – RMI registry port (must match {@code sae-nodes.json} for this SAE)</li>
     *   <li>{@code QKD_BASE_URL}              – KME API base URL for {@link Qkd014Client}</li>
     *   <li>{@code QKD_HSM_KEY_ALIAS}         – CryptoServer keystore alias (CertGenerator QuKayDee import)</li>
     *   <li>{@code QKD_TRUSTSTORE_PATH}       – QuKayDee KME server CA (PKCS#12 or PEM; public only)</li>
     *   <li>{@code TLS_NODE_ID}               – HSM PQMI key name + leaf cert selector ({@code certs/{TLS_NODE_ID}.pem})</li>
     *   <li>{@code DB_URL}                    – SQLite JDBC URL for this node (e.g. {@code jdbc:sqlite:data/qkd-sae-1.db})</li>
     * </ul>
     *
     * <p>HSM connection ({@code HSM_DEVICE}, {@code HSM_USER}, {@code HSM_PIN}, …) comes from
     * {@code env/hsm.env} — source it together with the node's own env file before running
     * {@code mvn exec:java} (see {@code src/SaeNode/README.md}).
     *
     * <p>Optional environment variables:
     * <ul>
     *   <li>{@code NODE_HOSTNAME}            – RMI bind address (default: {@code 127.0.0.1})</li>
     *   <li>{@code USB_SERIAL_PORT}          – CDC path, or {@code auto} / {@code scan}; {@code none} skips USB</li>
     *   <li>{@code USB_BAUD_RATE}            – serial baud (default: {@code 115200})</li>
     *   <li>{@code RECORD_RETENTION_DAYS}    – delete DB rows older than this many days (default: {@code 14})</li>
     *   <li>{@code QKD_TRUSTSTORE_PASSWORD}  – truststore password if PKCS#12
     *       (falls back to {@code QKD_KEYSTORE_PASSWORD}; stdin prompt if neither is set)</li>
     *   <li>{@code PQC_CERTS_DIR}             – cert directory (default: {@code certs})</li>
     *   <li>{@code APP_LOG}                  – {@code FULL} prints every log; {@code TERMINAL}
     *       (default) prints only operator prompts. SQLite logging stays on either way.</li>
     * </ul>
     *
     * <p>Node identity certs are HSM-backed: {@code $PQC_CERTS_DIR/<TLS_NODE_ID>.pem} (leaf)
     * and {@code $PQC_CERTS_DIR/ca/root-ca.pem} (RMI trust). Device {@code PROVISION} TLS
     * presents the same node identity but trusts {@code $PQC_CERTS_DIR/ca/client_ca.pem}.
     * Provision with {@code CertGenerator}.
     */
    public static void main(String[] args) throws InterruptedException {
        AppLogging.bindTerminal();
        SqliteLogging.install(DatabaseConfig.getDbUrl());
        String saeId = requireEnv("SAE_ID");
        int rmiPort = requireEnvInt("NODE_RMI_PORT");
        String qkdBaseUrl = requireEnv("QKD_BASE_URL");

        String hostname = envOrDefault("NODE_HOSTNAME", "127.0.0.1");
        String tlsNodeId = requireEnv("TLS_NODE_ID");

        HikariDataSource dataSource = DB.createDataSource();
        try (var connection = dataSource.getConnection()) {
            LOG.info("Connected to SQLite: " + DatabaseConfig.getDbUrl());
        } catch (SQLException e) {
            LOG.log(Level.SEVERE, "Database connection failed: " + e.getMessage(), e);
            dataSource.close();
            System.exit(1);
        }

        try {
            Pqmi pqmi = Pqmi.fromEnvironment();
            Qkd014Client qkdClient = loadQkdClient(qkdBaseUrl, pqmi);

            Address address = new Address(hostname, rmiPort);
            NodeRef selfRef = new NodeRef(address, saeId);

            Node node = new NodeBootstrap(dataSource).create(selfRef, tlsNodeId, qkdClient);
            node.usePqmi(pqmi);
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                node.close();
                dataSource.close();
            }, "node-shutdown"));

            node.start();
            LOG.info("Node " + saeId + " started — RMI " + address);

            Thread.currentThread().join();
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Failed to start node: " + ex.getMessage(), ex);
            dataSource.close();
            System.exit(1);
        }
    }

    private static Qkd014Client loadQkdClient(String qkdBaseUrl, Pqmi pqmi) throws Exception {
        String hsmAlias = requireEnv("QKD_HSM_KEY_ALIAS");
        String truststorePath = requireEnv("QKD_TRUSTSTORE_PATH");
        char[] password = EnvSecrets.envOrScan(
                "QKD_TRUSTSTORE_PASSWORD", "QKD_KEYSTORE_PASSWORD").toCharArray();
        return Qkd014Client.fromHsm(
                pqmi,
                qkdBaseUrl,
                hsmAlias,
                Path.of(truststorePath),
                password,
                SoftwareTls.TlsProfile.CLASSICAL
        );
    }

    private static String env(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private static String envOrDefault(String name, String defaultValue) {
        String value = env(name);
        return value == null ? defaultValue : value;
    }

    private static String requireEnv(String name) {
        String value = env(name);
        if (value == null) {
            throw new IllegalStateException("Required environment variable is not set: " + name);
        }
        return value;
    }

    private static int requireEnvInt(String name) {
        String value = requireEnv(name);
        try {
            int parsed = Integer.parseInt(value);
            if (parsed <= 0 || parsed > 65535) {
                throw new IllegalStateException(name + " must be between 1 and 65535, got: " + parsed);
            }
            return parsed;
        } catch (NumberFormatException ex) {
            throw new IllegalStateException(name + " must be a valid integer, got: " + value);
        }
    }

    private static ThreadFactory newDaemonFactory(String prefix) {
        return runnable -> {
            Thread thread = new Thread(runnable);
            thread.setName(prefix + "-" + thread.threadId());
            thread.setDaemon(true);
            return thread;
        };
    }
}
