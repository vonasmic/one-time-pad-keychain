package fel.cvut.node;

import fel.cvut.db.DB;
import fel.cvut.db.DatabaseConfig;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.KeyItem;
import fel.cvut.qkd.KeyItems;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import fel.cvut.terminal.TerminalOutput;
import fel.cvut.tls.NodeTls;
import fel.cvut.utimaco.Pqmi;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaxxer.hikari.HikariDataSource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
    private final Qkd014Client qkdClient;
    private final Consumer<SSLSocket> commandHandler;
    private final InputHandler inputHandler;
    private final NodeCommands nodeCommands;
    private final AtomicRecordStateMap localRecordStateMap;
    private final SharedKeyMaterialStore sharedKeyMaterialStore;
    private final ObjectMapper objectMapper;
    private final RmiManager rmiManager;
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
     * @param qkdClient              QKD client for KME API access
     * @param commandHandler         per-connection handler for command sockets
     * @param objectMapper           JSON mapper shared with persistence
     * @param localRecordStateMap    local record metadata map
     * @param sharedKeyMaterialStore encrypted shared-key material store
     * @param nodeCommands           RMI command implementation
     * @param rmiManager             RMI lifecycle manager
     */
    public Node(
            NodeRef selfRef,
            String tlsNodeId,
            int commandServerPort,
            Qkd014Client qkdClient,
            Consumer<SSLSocket> commandHandler,
            ObjectMapper objectMapper,
            AtomicRecordStateMap localRecordStateMap,
            SharedKeyMaterialStore sharedKeyMaterialStore,
            NodeCommands nodeCommands,
            RmiManager rmiManager
    ) {
        this.selfRef = Objects.requireNonNull(selfRef, "selfRef must not be null");
        this.tlsNodeId = Objects.requireNonNull(tlsNodeId, "tlsNodeId must not be null");
        this.commandServerPort = commandServerPort;
        this.qkdClient = Objects.requireNonNull(qkdClient, "qkdClient must not be null");
        this.commandHandler = Objects.requireNonNull(commandHandler, "commandHandler must not be null");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.localRecordStateMap = Objects.requireNonNull(localRecordStateMap, "localRecordStateMap must not be null");
        this.sharedKeyMaterialStore = Objects.requireNonNull(
                sharedKeyMaterialStore,
                "sharedKeyMaterialStore must not be null"
        );
        this.nodeCommands = Objects.requireNonNull(nodeCommands, "nodeCommands must not be null");
        this.rmiManager = Objects.requireNonNull(rmiManager, "rmiManager must not be null");
        this.inputHandler = new InputHandler();
        this.executor = Executors.newCachedThreadPool(newDaemonFactory("node-worker"));
    }

    /**
     * Starts RMI first and then the TLS command server accept loop.
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
            tlsContext = NodeTls.createContextForNode(pqmi, tlsNodeId);

            rmiManager.start(nodeCommands, tlsContext);
            commandServer = NodeTls.createServerSocket(
                    commandServerPort,
                    tlsContext,
                    NodeTls.TlsProfile.PURE_PQC,
                    true
            );
            running = true;
            executor.submit(this::acceptLoop);
        } catch (Exception ex) {
            closeHsmResources();
            rmiManager.stop();
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
        try {
            socket.startHandshake();
            List<RmiManager.SaeNode> friendlySaeNodes = RmiManager.getKnownSaeNodes().stream()
                    .filter(node -> node != null && !Objects.equals(node.saeId(), selfRef.getNodeId()))
                    .toList();
            ClientRecord clientRecord = inputHandler.handleInput(socket.getInputStream(), friendlySaeNodes);
            System.out.println("Created client record from input: " + clientRecord);
            Optional<String> payloadToReturn = processClientRecord(clientRecord);
            if (payloadToReturn.isPresent()) {
                String payload = payloadToReturn.get();
                socket.getOutputStream().write(payload.getBytes(StandardCharsets.UTF_8));
                socket.getOutputStream().flush();
                System.out.println("Sent payload to TLS client (" + payload.length() + " bytes)");
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
            }
            commandHandler.accept(socket);
        } catch (Exception ex) {
            logSocketFailure(ex);
        } finally {
            closeTlsClientSocket(socket);
        }
    }

    private static void logSocketFailure(Exception ex) {
        System.err.println("Socket input handling failed: " + ex.getMessage());
        Throwable cause = ex.getCause();
        if (cause != null) {
            System.err.println("  Cause: " + cause.getMessage());
        }
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

    private Optional<String> processClientRecord(ClientRecord clientRecord)
            throws RemoteException, Qkd014ClientException, IOException, NotBoundException {
        while (true) {
            String localSaeId = selfRef.getNodeId();
            ClientRecord.ClientHeader clientHeader = clientRecord.getClientHeader();
            AtomicRecordStateMap.StartRecordInsertOutcome insertOutcome = localRecordStateMap.startRecordInsert(
                    clientHeader,
                    localSaeId
            );

            if (insertOutcome == AtomicRecordStateMap.StartRecordInsertOutcome.INSERTED) {
                try {
                    KeyContainer keyContainer = qkdClient.getKey(clientHeader.saeId(), 1, null);
                    List<KeyItem> keys = KeyItems.extractKeys(keyContainer);
                    List<String> keyIds = KeyItems.extractKeyIds(keys);
                    List<String> keyMaterial = KeyItems.extractKeyMaterial(keys);
                    ClientRecord completedRecord = clientRecord.withPayload(keyIds);
                    if (orchestrateTargetInsertThenFinalizeOrigin(completedRecord, localSaeId)) {
                        System.out.println(
                                "Record finalized through target for hashes "
                                        + clientHeader.clientHash1()
                                        + " / "
                                        + clientHeader.clientHash2()
                        );
                        return Optional.of(objectMapper.writeValueAsString(keyMaterial));
                    }
                    System.out.println(
                            "No payload returned because target/origin finalization failed for hashes "
                                    + clientHeader.clientHash1()
                                    + " / "
                                    + clientHeader.clientHash2()
                    );
                    return Optional.empty();
                } catch (Exception ex) {
                    tryDeleteLocalRecord(
                            clientHeader.clientHash1(),
                            clientHeader.clientHash2(),
                            localSaeId,
                            "rolled back after key fetch or target orchestration failed"
                    );
                    throw ex;
                }
            }

            if (insertOutcome == AtomicRecordStateMap.StartRecordInsertOutcome.RECORD_AVAILABLE
                    || insertOutcome == AtomicRecordStateMap.StartRecordInsertOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE) {
                SharedPayloadResolution fallbackResolution = resolveSharedPayloadFallback(clientHeader, localSaeId);
                if (fallbackResolution.restartInsert()) {
                    continue;
                }
                return fallbackResolution.payload();
            }

            System.out.println("Skipping record processing due to map insertion outcome: " + insertOutcome);
            return Optional.empty();
        }
    }

    private SharedPayloadResolution resolveSharedPayloadFallback(
            ClientRecord.ClientHeader clientHeader,
            String localSaeId
    )
            throws IOException, RemoteException, NotBoundException {
        String clientHash1 = clientHeader.clientHash1();
        String clientHash2 = clientHeader.clientHash2();
        Optional<AtomicRecordStateMap.RecordMetadata> existingMetadata = localRecordStateMap.get(clientHash1, clientHash2);
        if (existingMetadata.isEmpty()) {
            System.out.println("Shared record fallback requested but no metadata found for hashes "
                    + clientHash1 + " / " + clientHash2);
            return SharedPayloadResolution.noPayload();
        }

        AtomicRecordStateMap.RecordMetadata metadata = existingMetadata.get();
        if (Objects.equals(metadata.issuingSaeId(), localSaeId)) {
            boolean deleteShared = promptDelete(metadata, clientHeader);
            if (!deleteShared) {
                return SharedPayloadResolution.noPayload();
            }
            forceDeleteLocalRecord(clientHash1, clientHash2, "user confirmed deletion of shared record");
            forceDeleteRemoteRecord(metadata.saeId(), clientHash1, clientHash2);
            return SharedPayloadResolution.forRestartInsert();
        }

        forceDeleteRemoteRecord(metadata.issuingSaeId(), clientHash1, clientHash2);
        Optional<List<String>> keyMaterial = sharedKeyMaterialStore.readPayload(
                clientHash1,
                clientHash2
        );
        forceDeleteLocalRecord(clientHash1, clientHash2, "shared payload delivered to requesting SAE");
        if (keyMaterial.isEmpty()) {
            System.out.println(
                    "Shared record present in map but no shared key material found for hashes "
                            + clientHash1
                            + " / "
                            + clientHash2
            );
            return SharedPayloadResolution.noPayload();
        }

        sharedKeyMaterialStore.remove(
                clientHash1,
                clientHash2
        );
        System.out.println(
                "Returned shared payload and removed record for hashes "
                        + clientHash1
                        + " / "
                        + clientHash2
        );
        return SharedPayloadResolution.withPayload(objectMapper.writeValueAsString(keyMaterial.get()));
    }

    private record SharedPayloadResolution(Optional<String> payload, boolean restartInsert) {
        private static SharedPayloadResolution noPayload() {
            return new SharedPayloadResolution(Optional.empty(), false);
        }

        private static SharedPayloadResolution forRestartInsert() {
            return new SharedPayloadResolution(Optional.empty(), true);
        }

        private static SharedPayloadResolution withPayload(String payload) {
            return new SharedPayloadResolution(Optional.of(payload), false);
        }
    }

    private boolean promptDelete(
            AtomicRecordStateMap.RecordMetadata metadata,
            ClientRecord.ClientHeader clientHeader
    ) {
        String message = "Secret keys already shared for hashes "
                + clientHeader.clientHash1()
                + " / "
                + clientHeader.clientHash2()
                + " with SAE id: "
                + metadata.saeId()
                + " at "
                + metadata.dateOfCreation();
        return TerminalOutput.promptDeletion(message);
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
        AtomicRecordStateMap.RecordMetadata removed = remoteNode.removeRecord(clientHash1, clientHash2);
        if (removed != null) {
            System.out.println(
                    "Deleted remote record on SAE "
                            + saeId
                            + " for hashes "
                            + clientHash1
                            + " / "
                            + clientHash2
            );
        }
    }

    private boolean orchestrateTargetInsertThenFinalizeOrigin(ClientRecord completedRecord, String localSaeId)
            throws RemoteException, NotBoundException {
        ClientRecord.ClientHeader header = completedRecord.getClientHeader();
        ClientRecord targetRecord = completedRecord.withSecondSaeId(localSaeId);
        try {
            NodeCommands targetNode = rmiManager.connectBySaeId(header.saeId());
            boolean targetSucceeded = targetNode.insert(targetRecord, localSaeId);
            if (!targetSucceeded) {
                tryDeleteLocalRecord(
                        header.clientHash1(),
                        header.clientHash2(),
                        localSaeId,
                        "rolled back after target SAE rejected insert"
                );
                System.out.println("Target SAE rejected record insert for hashes "
                        + header.clientHash1() + " / " + header.clientHash2());
                return false;
            }

            boolean originFinalized = localRecordStateMap.finishRecordInsert(header.clientHash1(), header.clientHash2());
            if (!originFinalized) {
                throw new IllegalStateException(
                        "Target finalized record, but origin failed to finalize local metadata for hashes "
                                + header.clientHash1()
                                + " / "
                                + header.clientHash2()
                );
            }
            return true;
        } catch (Exception ex) {
            tryDeleteLocalRecord(
                    header.clientHash1(),
                    header.clientHash2(),
                    localSaeId,
                    "rolled back after target SAE connection or insert failed"
            );
            throw ex;
        }
    }

    /**
     * Stops RMI, closes the TLS command server, and terminates worker threads.
     **/
    @Override
    public synchronized void close() {
        if (!running && commandServer == null) {
            executor.shutdownNow();
            return;
        }

        running = false;
        rmiManager.stop();

        SSLServerSocket localServer = commandServer;
        commandServer = null;
        if (localServer != null) {
            try {
                localServer.close();
            } catch (IOException ex) {
                System.err.println("TLS command server close failed: " + ex.getMessage());
            }
        }
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
     *   <li>{@code QKD_BASE_URL}              – KME API base URL for {@link Qkd014Client}</li>
     *   <li>{@code QKD_HSM_KEY_ALIAS}         – CryptoServer keystore alias (CertGenerator option 2)</li>
     *   <li>{@code QKD_TRUSTSTORE_PATH}       – QuKayDee KME server CA (PKCS#12 or PEM; public only)</li>
     *   <li>{@code TLS_NODE_ID}               – HSM PQMI key name + leaf cert selector ({@code certs/{TLS_NODE_ID}.pem})</li>
     *   <li>{@code DB_URL}                    – PostgreSQL JDBC URL for this node (e.g. {@code jdbc:postgresql://localhost:5432/qkd-db-sae-1})</li>
     *   <li>{@code DB_USERNAME}               – PostgreSQL user</li>
     *   <li>{@code DB_PASSWORD}               – PostgreSQL password</li>
     * </ul>
     *
     * <p>HSM connection ({@code HSM_DEVICE}, {@code HSM_USER}, {@code HSM_PIN}, …) comes from
     * {@code env/hsm.env} — use {@code ./run-node.sh} which sources it automatically.
     *
     * <p>Optional environment variables:
     * <ul>
     *   <li>{@code NODE_HOSTNAME}           – RMI bind address (default: {@code 127.0.0.1})</li>
     *   <li>{@code QKD_TRUSTSTORE_PASSWORD}  – truststore password if PKCS#12 (default: {@code password})</li>
     *   <li>{@code PQC_CERTS_DIR}             – cert directory (default: {@code certs})</li>
     * </ul>
     *
     * <p>Node identity certs are HSM-backed: {@code $PQC_CERTS_DIR/<TLS_NODE_ID>.pem} (leaf)
     * and {@code $PQC_CERTS_DIR/root-ca.pem} (trust). Provision with {@code CertGenerator}.
     */
    public static void main(String[] args) throws InterruptedException {
        String saeId = requireEnv("SAE_ID");
        int rmiPort = requireEnvInt("NODE_RMI_PORT");
        int commandPort = requireEnvInt("NODE_NATIVE_PORT");
        String qkdBaseUrl = requireEnv("QKD_BASE_URL");

        String hostname = envOrDefault("NODE_HOSTNAME", "127.0.0.1");
        String tlsNodeId = requireEnv("TLS_NODE_ID");

        HikariDataSource dataSource = DB.createDataSource();
        try (var connection = dataSource.getConnection()) {
            System.out.println("Connected to PostgreSQL: " + DatabaseConfig.getDbUrl());
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
                    qkdClient,
                    socket -> {}
            );
            node.usePqmi(pqmi);
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                node.close();
                dataSource.close();
            }, "node-shutdown"));

            node.start();
            System.out.println("Node " + saeId + " started — RMI " + address + ", TLS command port " + commandPort);

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
        char[] password = envOrDefault("QKD_TRUSTSTORE_PASSWORD",
                envOrDefault("QKD_KEYSTORE_PASSWORD", "password")).toCharArray();
        return Qkd014Client.fromHsm(
                pqmi,
                qkdBaseUrl,
                hsmAlias,
                Path.of(truststorePath),
                password,
                NodeTls.TlsProfile.CLASSICAL
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
