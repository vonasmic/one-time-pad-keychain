package fel.cvut.node;

import fel.cvut.TLS.NativeTlsServer;
import fel.cvut.db.DB;
import fel.cvut.db.DatabaseConfig;
import fel.cvut.TLS.TLSSocket;
import fel.cvut.bouncyCastle.BouncyCastleTLS;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.StubRecordFileStore;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.KeyItem;
import fel.cvut.qkd.KeyItems;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import fel.cvut.terminal.TerminalOutput;
import com.fasterxml.jackson.databind.ObjectMapper;

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
 *   <li>Native TLS command server for inbound command sockets</li>
 * </ul>
 */
public class Node implements AutoCloseable {

    private final NodeRef selfRef;
    private final String tlsNodeId;
    private final int nativeServerPort;
    private final Qkd014Client qkdClient;
    private final Consumer<TLSSocket> commandHandler;
    private final InputHandler inputHandler;
    private final NodeCommands nodeCommands;
    private final AtomicRecordStateMap localRecordStateMap;
    private final StubRecordFileStore stubRecordFileStore;
    private final ObjectMapper objectMapper;
    private final RmiManager rmiManager;
    private final ExecutorService executor;

    private volatile boolean running;
    private volatile NativeTlsServer nativeServer;

    /**
     * Creates a node instance without starting networking components.
     *
     * @param selfRef          local node reference
     * @param tlsNodeId        TLS identity used for RMI PQC context loading
     * @param nativeServerPort native command server listening port
     * @param qkdClient        QKD client for KME API access
     * @param commandHandler   per-connection handler for native command sockets
     */
    public Node(
            NodeRef selfRef,
            String tlsNodeId,
            int nativeServerPort,
            Qkd014Client qkdClient,
            Consumer<TLSSocket> commandHandler
    ) {
        this.selfRef = Objects.requireNonNull(selfRef, "selfRef must not be null");
        this.tlsNodeId = Objects.requireNonNull(tlsNodeId, "tlsNodeId must not be null");
        this.nativeServerPort = nativeServerPort;
        this.qkdClient = Objects.requireNonNull(qkdClient, "qkdClient must not be null");
        this.commandHandler = Objects.requireNonNull(commandHandler, "commandHandler must not be null");
        this.inputHandler = new InputHandler();
        this.objectMapper = new ObjectMapper();

        Address address = Objects.requireNonNull(selfRef.getAddress(), "selfRef.address must not be null");
        this.localRecordStateMap = new AtomicRecordStateMap(selfRef.getNodeId());
        this.stubRecordFileStore = new StubRecordFileStore();
        this.nodeCommands = new NodeCommandsService(selfRef, localRecordStateMap, qkdClient);
        this.rmiManager = new RmiManager(address, this.tlsNodeId);
        this.executor = Executors.newCachedThreadPool(newDaemonFactory("node-worker"));
    }

    /**
     * Starts RMI first and then native command server accept loop.
     */
    public synchronized void start() {
        if (running) {
            return;
        }

        rmiManager.start(nodeCommands);

        try {
            nativeServer = new NativeTlsServer(nativeServerPort);
            running = true;
            executor.submit(this::acceptLoop);
        } catch (RuntimeException ex) {
            rmiManager.stop();
            nativeServer = null;
            throw new IllegalStateException("Failed to start native TLS server.", ex);
        }
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
            NativeTlsServer localServer = nativeServer;
            if (localServer == null) {
                return;
            }

            try {
                TLSSocket socket = localServer.accept();
                executor.submit(() -> handleConnection(socket));
            } catch (RuntimeException ex) {
                if (running) {
                    System.err.println("Native TLS accept loop failed: " + ex.getMessage());
                }
                return;
            }
        }
    }

    private void handleConnection(TLSSocket socket) {
        try (TLSSocket managedSocket = socket) {
            List<RmiManager.SaeNode> friendlySaeNodes = RmiManager.getKnownSaeNodes().stream()
                    .filter(node -> node != null && !Objects.equals(node.saeId(), selfRef.getNodeId()))
                    .toList();
            ClientRecord clientRecord = inputHandler.handleInput(managedSocket, friendlySaeNodes);
            System.out.println("Created client record from input: " + clientRecord);
            Optional<String> payloadToReturn = processClientRecord(clientRecord);
            if (payloadToReturn.isPresent()) {
                String payload = payloadToReturn.get();
                managedSocket.write(payload.getBytes(StandardCharsets.UTF_8));
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
            commandHandler.accept(managedSocket);
        } catch (Exception ex) {
            System.err.println("Socket input handling failed: " + ex.getMessage());
            Throwable cause = ex.getCause();
            if (cause != null) {
                System.err.println("  Cause: " + cause.getMessage());
             }
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
                    localRecordStateMap.tryDelete(
                            clientHeader.clientHash1(),
                            clientHeader.clientHash2(),
                            localSaeId
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
            localRecordStateMap.forceDelete(clientHash1, clientHash2);
            forceDeleteRemoteRecord(metadata.saeId(), clientHash1, clientHash2);
            return SharedPayloadResolution.forRestartInsert();
        }

        forceDeleteRemoteRecord(metadata.issuingSaeId(), clientHash1, clientHash2);
        Optional<List<String>> keyMaterial = stubRecordFileStore.readPayload(
                clientHash1,
                clientHash2,
                metadata.issuingSaeId()
        );
        localRecordStateMap.forceDelete(clientHash1, clientHash2);
        if (keyMaterial.isEmpty()) {
            System.out.println(
                    "Shared record present in map but no stub payload found for hashes "
                            + clientHash1
                            + " / "
                            + clientHash2
            );
            return SharedPayloadResolution.noPayload();
        }

        stubRecordFileStore.remove(
                clientHash1,
                clientHash2,
                metadata.issuingSaeId()
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

    private void forceDeleteRemoteRecord(String saeId, String clientHash1, String clientHash2)
            throws RemoteException, NotBoundException {
        NodeCommands remoteNode = RmiManager.connectBySaeId(saeId, tlsNodeId);
        remoteNode.removeRecord(clientHash1, clientHash2);
    }

    private boolean orchestrateTargetInsertThenFinalizeOrigin(ClientRecord completedRecord, String localSaeId)
            throws RemoteException, NotBoundException {
        ClientRecord.ClientHeader header = completedRecord.getClientHeader();
        ClientRecord targetRecord = completedRecord.withSecondSaeId(localSaeId);
        try {
            NodeCommands targetNode = RmiManager.connectBySaeId(header.saeId(), tlsNodeId);
            boolean targetSucceeded = targetNode.insert(targetRecord, localSaeId);
            if (!targetSucceeded) {
                localRecordStateMap.tryDelete(header.clientHash1(), header.clientHash2(), localSaeId);
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
            localRecordStateMap.tryDelete(header.clientHash1(), header.clientHash2(), localSaeId);
            throw ex;
        }
    }

    /**
     * Stops RMI, closes native server, and terminates worker thread.
     **/
    @Override
    public synchronized void close() {
        if (!running && nativeServer == null) {
            executor.shutdownNow();
            return;
        }

        running = false;
        rmiManager.stop();

        NativeTlsServer localServer = nativeServer;
        nativeServer = null;
        if (localServer != null) {
            try {
                localServer.close();
            } catch (RuntimeException ex) {
                System.err.println("Native TLS server close failed: " + ex.getMessage());
            }
        }
        executor.shutdownNow();
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
     *   <li>{@code NODE_NATIVE_PORT} – native TLS command server port</li>
     *   <li>{@code QKD_BASE_URL}              – KME API base URL for {@link Qkd014Client}</li>
     *   <li>{@code QKD_CLIENT_KEYSTORE_PATH}  – QuKayDee SAE client PKCS#12 for mTLS</li>
     *   <li>{@code QKD_TRUSTSTORE_PATH}       – QuKayDee KME server CA PKCS#12</li>
     *   <li>{@code TLS_NODE_ID}               – TLS identity for RMI PQC context and cert resolution</li>
     *   <li>{@code DB_URL}                    – PostgreSQL JDBC URL for this node (e.g. {@code jdbc:postgresql://localhost:5432/qkd-db-sae-1})</li>
     *   <li>{@code DB_USERNAME}               – PostgreSQL user</li>
     *   <li>{@code DB_PASSWORD}               – PostgreSQL password</li>
     * </ul>
     *
     * <p>Optional environment variables:
     * <ul>
     *   <li>{@code NODE_HOSTNAME}           – RMI bind address (default: {@code 127.0.0.1})</li>
     *   <li>{@code QKD_KEYSTORE_PASSWORD}   – QKD keystore/truststore password (default: {@code password})</li>
     *   <li>{@code PQC_KEYSTORE_PATH}       – explicit PKCS#12 keystore (with {@code PQC_TRUSTSTORE_PATH})</li>
     *   <li>{@code PQC_TRUSTSTORE_PATH}     – explicit PKCS#12 truststore (with {@code PQC_KEYSTORE_PATH})</li>
     *   <li>{@code PQC_KEYSTORE_PASSWORD}   – PQC keystore/truststore password (default: {@code password})</li>
     *   <li>{@code PQC_CERTS_DIR}             – cert directory when paths are omitted (default: {@code certs})</li>
     * </ul>
     *
     * <p>When keystore paths are omitted, certs are resolved as
     * {@code $PQC_CERTS_DIR/<TLS_NODE_ID>.p12} and {@code $PQC_CERTS_DIR/root-ca.p12}.
     */
    public static void main(String[] args) throws InterruptedException {
        String saeId = requireEnv("SAE_ID");
        int rmiPort = requireEnvInt("NODE_RMI_PORT");
        int nativePort = requireEnvInt("NODE_NATIVE_PORT");
        String qkdBaseUrl = requireEnv("QKD_BASE_URL");

        String hostname = envOrDefault("NODE_HOSTNAME", "127.0.0.1");
        String tlsNodeId = requireEnv("TLS_NODE_ID");

        try (var connection = DB.connect()) {
            System.out.println("Connected to PostgreSQL: " + DatabaseConfig.getDbUrl());
        } catch (SQLException e) {
            System.err.println("Database connection failed: " + e.getMessage());
            System.exit(1);
        }

        try {
            Qkd014Client qkdClient = loadQkdClient(qkdBaseUrl);

            Address address = new Address(hostname, rmiPort);
            NodeRef selfRef = new NodeRef(address, saeId);

            Node node = new Node(
                    selfRef,
                    tlsNodeId,
                    nativePort,
                    qkdClient,
                    socket -> {}
            );
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                node.close();
                DB.close();
            }, "node-shutdown"));

            node.start();
            System.out.println("Node " + saeId + " started — RMI " + address + ", native port " + nativePort);

            Thread.currentThread().join();
        } catch (Exception ex) {
            System.err.println("Failed to start node: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private static Qkd014Client loadQkdClient(String qkdBaseUrl) throws Exception {
        String clientKeystorePath = requireEnv("QKD_CLIENT_KEYSTORE_PATH");
        String truststorePath = requireEnv("QKD_TRUSTSTORE_PATH");
        char[] password = envOrDefault("QKD_KEYSTORE_PASSWORD", "password").toCharArray();
        return Qkd014Client.fromPkcs12(
                qkdBaseUrl,
                Path.of(clientKeystorePath),
                password,
                Path.of(truststorePath),
                password,
                BouncyCastleTLS.TlsPolicy.defaultPolicy()
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
