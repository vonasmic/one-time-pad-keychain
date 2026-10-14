package fel.cvut.node;

import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.db.RecordRetention;
import fel.cvut.db.SharedKeyMaterialRepository;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.utimaco.HsmAesGcm;

import javax.sql.DataSource;
import java.util.Objects;

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
     * @param selfRef   local node reference
     * @param tlsNodeId TLS identity used for RMI PQC context loading
     * @param qkdClient QKD client for KME API access
     * @return configured node instance (not yet started)
     */
    public Node create(
            NodeRef selfRef,
            String tlsNodeId,
            Qkd014Client qkdClient
    ) {
        Objects.requireNonNull(selfRef, "selfRef must not be null");
        Objects.requireNonNull(selfRef.getAddress(), "selfRef.address must not be null");
        Objects.requireNonNull(qkdClient, "qkdClient must not be null");

        RecordRetention recordRetention = RecordRetention.fromEnvironment(dataSource);
        SharedKeyMaterialStore store = new SharedKeyMaterialStore(
                dataSource,
                sharedKeyMaterialRepository,
                clientRecordStateRepository,
                hsmAesGcm,
                objectMapper,
                recordRetention.retention()
        );
        AtomicRecordStateMap stateMap = new AtomicRecordStateMap(
                selfRef.getNodeId(),
                dataSource,
                clientRecordStateRepository,
                recordRetention.retention()
        );
        RmiManager rmiManager = RmiManager.fromEnvironment(selfRef);
        NodeCommands nodeCommands = new NodeCommandsService(selfRef, stateMap, qkdClient, store, rmiManager);

        return new Node(
                selfRef,
                tlsNodeId,
                qkdClient,
                stateMap,
                store,
                nodeCommands,
                rmiManager,
                recordRetention
        );
    }
}
