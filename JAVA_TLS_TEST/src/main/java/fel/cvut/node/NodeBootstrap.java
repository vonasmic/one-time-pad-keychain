package fel.cvut.node;

import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.db.SharedKeyMaterialRepository;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.utimaco.HsmAesGcm;

import javax.net.ssl.SSLSocket;
import javax.sql.DataSource;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Composition root that owns shared singletons and builds the {@link Node} object graph.
 */
public final class NodeBootstrap {

    private final DataSource dataSource;
    private final ObjectMapper objectMapper;
    private final HsmAesGcm hsmAesGcm;
    private final SharedKeyMaterialRepository sharedKeyMaterialRepository;
    private final ClientRecordStateRepository clientRecordStateRepository;

    public NodeBootstrap(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource must not be null");
        this.objectMapper = new ObjectMapper();
        this.hsmAesGcm = new HsmAesGcm();
        this.sharedKeyMaterialRepository = new SharedKeyMaterialRepository();
        this.clientRecordStateRepository = new ClientRecordStateRepository();
    }

    /**
     * Wires collaborators and returns a ready-to-start {@link Node}.
     *
     * @param selfRef           local node reference
     * @param tlsNodeId         TLS identity used for RMI PQC context loading
     * @param commandServerPort TLS command server listening port ({@code NODE_NATIVE_PORT})
     * @param qkdClient         QKD client for KME API access
     * @param commandHandler    per-connection handler for command sockets
     * @return configured node instance (not yet started)
     */
    public Node create(
            NodeRef selfRef,
            String tlsNodeId,
            int commandServerPort,
            Qkd014Client qkdClient,
            Consumer<SSLSocket> commandHandler
    ) {
        Objects.requireNonNull(selfRef, "selfRef must not be null");
        Objects.requireNonNull(selfRef.getAddress(), "selfRef.address must not be null");
        Objects.requireNonNull(qkdClient, "qkdClient must not be null");

        SharedKeyMaterialStore store = new SharedKeyMaterialStore(
                dataSource,
                sharedKeyMaterialRepository,
                hsmAesGcm,
                objectMapper
        );
        AtomicRecordStateMap stateMap = new AtomicRecordStateMap(
                selfRef.getNodeId(),
                dataSource,
                clientRecordStateRepository
        );
        NodeCommands nodeCommands = new NodeCommandsService(selfRef, stateMap, qkdClient, store);
        RmiManager rmiManager = new RmiManager(selfRef.getAddress());

        return new Node(
                selfRef,
                tlsNodeId,
                commandServerPort,
                qkdClient,
                commandHandler,
                objectMapper,
                stateMap,
                store,
                nodeCommands,
                rmiManager
        );
    }
}
