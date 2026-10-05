package fel.cvut.node;

import fel.cvut.db.DB;
import fel.cvut.db.DatabaseConfig;
import fel.cvut.db.RecordRetention;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import fel.cvut.se.EnvSecrets;
import fel.cvut.se.SeKemFill;
import fel.cvut.se.SeProvisionAck;
import fel.cvut.se.SeSessionBinding;
import fel.cvut.se.SeSessionUplink;
import fel.cvut.tls.HsmNodeTls;
import fel.cvut.tls.SoftwareTls;
import fel.cvut.utimaco.Pqmi;
import com.zaxxer.hikari.HikariDataSource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
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
import java.util.function.Consumer;

/**
 * Main node orchestration class.
 *
 * <p>Starts and manages:
 * <ul>
 *   <li>RMI communication for inter-node calls</li>
 *   <li>QKD API access via {@link Qkd014Client}</li>
 *   <li>TLS command server for inbound command sockets</li>
 * </ul>
 */
public class Node implements AutoCloseable {

    private final NodeRef selfRef;
    private final String tlsNodeId;
    private final int commandServerPort;
    private final int terminalGatewayPort;
    private final Qkd014Client qkdClient;
    private final Consumer<SSLSocket> commandHandler;
    private final InputHandler inputHandler;
    private final TerminalGateway terminalGateway;
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

    private volatile boolean running;
    private volatile SSLServerSocket commandServer;

    /**
     * Creates a node instance without starting networking components.
     *
     * @param selfRef                local node reference
     * @param tlsNodeId              TLS identity used for RMI PQC context loading
     * @param commandServerPort      TLS command server listening port ({@code NODE_NATIVE_PORT})
     * @param terminalGatewayPort    TLS terminal gateway port the standalone terminal app connects to
     *                               ({@code NODE_TERMINAL_PORT}) — uses the same TLS bootstrap as RMI
     * @param qkdClient              QKD client for KME API access
     * @param commandHandler         per-connection handler for command sockets
     * @param localRecordStateMap    local record metadata map
     * @param sharedKeyMaterialStore encrypted shared-key material store
     * @param nodeCommands           RMI command implementation
     * @param rmiManager             RMI lifecycle manager
     * @param recordRetention        daily {@code client_record_state} purge
     */
    public Node(
            NodeRef selfRef,
            String tlsNodeId,
            int commandServerPort,
            int terminalGatewayPort,
            Qkd014Client qkdClient,
            Consumer<SSLSocket> commandHandler,
            AtomicRecordStateMap localRecordStateMap,
            SharedKeyMaterialStore sharedKeyMaterialStore,
            NodeCommands nodeCommands,
            RmiManager rmiManager,
            RecordRetention recordRetention
    ) {
        this.selfRef = Objects.requireNonNull(selfRef, "selfRef must not be null");
        this.tlsNodeId = Objects.requireNonNull(tlsNodeId, "tlsNodeId must not be null");
        this.commandServerPort = commandServerPort;
        this.terminalGatewayPort = terminalGatewayPort;
        this.qkdClient = Objects.requireNonNull(qkdClient, "qkdClient must not be null");
        this.commandHandler = Objects.requireNonNull(commandHandler, "commandHandler must not be null");
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
        this.terminalGateway = new TerminalGateway(terminalGatewayPort);
        this.executor = Executors.newCachedThreadPool(newDaemonFactory("node-worker"));
    }

    /**
     * Starts RMI first, then the TLS command server accept loop and the terminal gateway.
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
            SSLContext commandServerContext = HsmNodeTls.createContextForCommandServer(pqmi, tlsNodeId);

            rmiManager.start(nodeCommands, tlsContext);
            commandServer = SoftwareTls.createServerSocket(
                    commandServerPort,
                    commandServerContext,
                    SoftwareTls.TlsProfile.PURE_PQC,
                    true
            );
            terminalGateway.start(tlsContext, executor);
            running = true;
            executor.submit(this::acceptLoop);
            recordRetention.start();
        } catch (Exception ex) {
            recordRetention.close();
            closeHsmResources();
            rmiManager.stop();
            terminalGateway.close();
            commandServer = null;
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

    private void acceptLoop() {
        while (running) {
            SSLServerSocket localServer = commandServer;
            if (localServer == null) {
                return;
            }

            try {
                SSLSocket socket = (SSLSocket) localServer.accept();
                executor.submit(() -> handleConnection(socket));
            } catch (IOException ex) {
                if (running) {
                    System.err.println("TLS command server accept loop failed: " + ex.getMessage());
                }
                return;
            }
        }
    }

    private void handleConnection(SSLSocket socket) {
        boolean handshakeDone = false;
        boolean outcomeReported = false;
        SeSessionBinding.HandshakeExporter exporter = new SeSessionBinding.HandshakeExporter();
        try {
            socket.setSoTimeout(100_000);
            exporter.attach(socket);
            socket.startHandshake();
            handshakeDone = true;
            List<RmiManager.SaeNode> friendlySaeNodes = RmiManager.getKnownSaeNodes().stream()
                    .filter(node -> node != null && !Objects.equals(node.saeId(), selfRef.getNodeId()))
                    .toList();
            InputHandler.OperatorSelection selection =
                    inputHandler.handleInput(socket, exporter.require(), friendlySaeNodes, terminalGateway);
            ProvisionSession.Outcome processResult;
            ProvisionSession session = provisionSession();
            while (true) {
                ClientRecord clientRecord = selection.clientRecord();
                SeSessionUplink uplink = selection.uplink();
                System.out.println("Created client record from LV uplink: " + clientRecord
                        + " (slotSize=" + uplink.slotSize()
                        + ", padCount=" + uplink.padCount()
                        + ", plainMax=" + uplink.plainMax() + ")");
                processResult = session.process(clientRecord, uplink);
                if (!(processResult instanceof ProvisionSession.Outcome.Reselect)) {
                    break;
                }
                selection = inputHandler.selectForUplink(uplink, friendlySaeNodes, terminalGateway);
            }
            ClientRecord clientRecord = selection.clientRecord();
            byte[] payload = switch (processResult) {
                case ProvisionSession.Outcome.Generated generated -> generated.payload();
                case ProvisionSession.Outcome.Existing existing -> existing.payload();
                default -> null;
            };
            if (payload != null) {
                socket.getOutputStream().write(payload);
                socket.getOutputStream().flush();
                System.out.println("Sent LV downlink to TLS client (" + payload.length + " bytes)");
                SeProvisionAck.read(socket.getInputStream());
                String status = SeProvisionAck.downloadMessage(payload.length);
                System.out.println(status);
                notifyOperator(status);
            } else {
                ClientRecord.ClientHeader header = clientRecord.getClientHeader();
                System.out.println(
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
            outcomeReported = true;
            commandHandler.accept(socket);
        } catch (Exception ex) {
            /* USB unplug. */
            if (handshakeDone && !outcomeReported) {
                notifyOperator(operatorFailure(ex));
            }
            if (handshakeDone) {
                logSocketFailure(ex);
            } else {
                System.err.println("TLS command handshake aborted: " + explainFailure(ex));
            }
        } finally {
            exporter.detach(socket);
            closeTlsClientSocket(socket);
        }
    }

    private void notifyOperator(String message) {
        try {
            terminalGateway.showMessage(message);
        } catch (Exception e) {
            System.err.println("Failed to send status to terminal: " + e.getMessage());
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
                this::forceDeleteRemoteRecord,
                kemFill
        );
    }

    private static void logSocketFailure(Exception ex) {
        System.err.println("Socket input handling failed: " + explainFailure(ex));
        Throwable cause = ex.getCause();
        int depth = 0;
        while (cause != null && depth < 6) {
            System.err.println("  Caused by: " + cause.getClass().getSimpleName()
                    + (cause.getMessage() == null || cause.getMessage().isBlank()
                    ? ""
                    : ": " + cause.getMessage()));
            cause = cause.getCause();
            depth++;
        }
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

    private static void closeTlsClientSocket(SSLSocket socket) {
        if (socket == null || socket.isClosed()) {
            return;
        }
        try {
            socket.close();
        } catch (IOException ex) {
            System.err.println("TLS client socket close failed: " + ex.getMessage());
        }
    }

    private boolean promptOperator(String message) throws IOException {
        try {
            return terminalGateway.confirmDeletion(message);
        } catch (IOException e) {
            throw e;
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
                .ifPresent(metadata -> System.out.println(
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
                .ifPresent(metadata -> System.out.println(
                        "Deleted local record for hashes "
                                + clientHash1
                                + " / "
                                + clientHash2
                                + ": "
                                + reason
                ));
    }

    private void forceDeleteRemoteRecord(String saeId, String clientHash1, String clientHash2)
            throws RemoteException, NotBoundException {
        NodeCommands remoteNode = rmiManager.connectBySaeId(saeId);
        AtomicRecordStateMap.RecordMetadata removed = remoteNode.removeRecord(clientHash2, clientHash1);
        if (removed != null) {
            System.out.println(
                    "Deleted remote record on SAE "
                            + saeId
                            + " for hashes "
                            + clientHash2
                            + " / "
                            + clientHash1
            );
        }
    }

    /**
     * Stops RMI, closes the TLS command server and terminal gateway, and terminates worker threads.
     **/
    @Override
    public synchronized void close() {
        if (!running && commandServer == null) {
            recordRetention.close();
            executor.shutdownNow();
            return;
        }

        running = false;
        rmiManager.stop();
        terminalGateway.close();

        SSLServerSocket localServer = commandServer;
        commandServer = null;
        if (localServer != null) {
            try {
                localServer.close();
            } catch (IOException ex) {
                System.err.println("TLS command server close failed: " + ex.getMessage());
            }
        }
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
     *   <li>{@code NODE_NATIVE_PORT} – TLS command server port</li>
     *   <li>{@code NODE_TERMINAL_PORT} – TLS terminal gateway port for the standalone terminal app</li>
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
     *   <li>{@code RECORD_RETENTION_DAYS}    – delete DB rows older than this many days (default: {@code 14})</li>
     *   <li>{@code QKD_TRUSTSTORE_PASSWORD}  – truststore password if PKCS#12
     *       (falls back to {@code QKD_KEYSTORE_PASSWORD}; stdin prompt if neither is set)</li>
     *   <li>{@code PQC_CERTS_DIR}             – cert directory (default: {@code certs})</li>
     * </ul>
     *
     * <p>Node identity certs are HSM-backed: {@code $PQC_CERTS_DIR/<TLS_NODE_ID>.pem} (leaf)
     * and {@code $PQC_CERTS_DIR/ca/root-ca.pem} (RMI / terminal trust). The TLS command server
     * presents the same node identity but trusts {@code $PQC_CERTS_DIR/ca/client_ca.pem} for
     * device mTLS. Provision with {@code CertGenerator}.
     */
    public static void main(String[] args) throws InterruptedException {
        String saeId = requireEnv("SAE_ID");
        int rmiPort = requireEnvInt("NODE_RMI_PORT");
        int commandPort = requireEnvInt("NODE_NATIVE_PORT");
        int terminalPort = requireEnvInt("NODE_TERMINAL_PORT");
        String qkdBaseUrl = requireEnv("QKD_BASE_URL");

        String hostname = envOrDefault("NODE_HOSTNAME", "127.0.0.1");
        String tlsNodeId = requireEnv("TLS_NODE_ID");

        HikariDataSource dataSource = DB.createDataSource();
        try (var connection = dataSource.getConnection()) {
            System.out.println("Connected to SQLite: " + DatabaseConfig.getDbUrl());
        } catch (SQLException e) {
            System.err.println("Database connection failed: " + e.getMessage());
            dataSource.close();
            System.exit(1);
        }

        try {
            Pqmi pqmi = Pqmi.fromEnvironment();
            Qkd014Client qkdClient = loadQkdClient(qkdBaseUrl, pqmi);

            Address address = new Address(hostname, rmiPort);
            NodeRef selfRef = new NodeRef(address, saeId);

            Node node = new NodeBootstrap(dataSource).create(
                    selfRef,
                    tlsNodeId,
                    commandPort,
                    terminalPort,
                    qkdClient,
                    socket -> {}
            );
            node.usePqmi(pqmi);
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                node.close();
                dataSource.close();
            }, "node-shutdown"));

            node.start();
            System.out.println("Node " + saeId + " started — RMI " + address
                    + ", TLS command port " + commandPort + ", terminal gateway port " + terminalPort);

            Thread.currentThread().join();
        } catch (Exception ex) {
            System.err.println("Failed to start node: " + ex.getMessage());
            ex.printStackTrace();
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
