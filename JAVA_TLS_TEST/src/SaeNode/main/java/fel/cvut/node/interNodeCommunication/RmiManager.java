package fel.cvut.node.interNodeCommunication;

import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.tls.NodeTls;
import fel.cvut.node.Address;

import fel.cvut.node.NodeCommands;
import java.io.InputStream;
import javax.net.ssl.SSLContext;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Manages RMI lifecycle for node-to-node communication with pure PQC TLS (ML-DSA + ML-KEM, TLS 1.3).
 */
public class RmiManager {

    public static final String COMM_INTERFACE_NAME = "NodeCommands";
    private static final String SAE_NODES_RESOURCE = "/sae-nodes.json";
    private static final NodeTls.TlsProfile TLS_PROFILE = NodeTls.TlsProfile.PURE_PQC;
    private static final Map<String, Address> ADDRESS_BY_SAE_ID = loadSaeNodeAddresses();
    private static final List<SaeNode> KNOWN_SAE_NODES = loadKnownSaeNodes();

    /** JVM-local TLS context for RMI sockets — must not be stored on serializable socket factories. */
    private static volatile SSLContext installedTlsContext;

    private final Address myAddress;

    private Registry registry;
    private NodeCommands messageReceiver;
    private boolean running = false;

    public RmiManager(Address myAddress) {
        this.myAddress = Objects.requireNonNull(myAddress, "myAddress must not be null");
    }

    /**
     * Start exporting node commands over RMI/TLS.
     */
    public synchronized void start(NodeCommands receiver, SSLContext tlsContext) {
        if (running) {
            return;
        }

        installedTlsContext = Objects.requireNonNull(tlsContext, "tlsContext must not be null");
        System.setProperty("java.rmi.server.hostname", myAddress.hostname);
        try {
            this.messageReceiver = Objects.requireNonNull(receiver, "receiver must not be null");

            PqcTlsRmiClientSocketFactory clientFactory = new PqcTlsRmiClientSocketFactory();
            PqcTlsRmiServerSocketFactory serverFactory = new PqcTlsRmiServerSocketFactory(true);

            NodeCommands skeleton = (NodeCommands) UnicastRemoteObject.exportObject(
                    messageReceiver,
                    40000 + myAddress.port,
                    clientFactory,
                    serverFactory
            );

            try {
                registry = LocateRegistry.getRegistry(myAddress.hostname, myAddress.port, clientFactory);
                registry.rebind(COMM_INTERFACE_NAME, skeleton);
            } catch (RemoteException ex) {
                registry = LocateRegistry.createRegistry(myAddress.port, clientFactory, serverFactory);
                registry.rebind(COMM_INTERFACE_NAME, skeleton);
            }
            running = true;
        } catch (Exception e) {
            installedTlsContext = null;
            throw new IllegalStateException("Failed to start RMI manager.", e);
        }
    }

    /**
     * Stop RMI listener and unexport object.
     */
    public synchronized void stop() {
        if (!running) {
            return;
        }
        try {
            if (registry != null) {
                registry.unbind(COMM_INTERFACE_NAME);
            }
        } catch (Exception ignored) {
            // Best-effort shutdown.
        }
        try {
            if (messageReceiver != null) {
                UnicastRemoteObject.unexportObject(messageReceiver, true);
            }
        } catch (Exception ignored) {
            // Best-effort shutdown.
        }
        messageReceiver = null;
        registry = null;
        installedTlsContext = null;
        running = false;
    }

    public boolean isRunning() {
        return running;
    }

    public NodeCommands getMessageReceiver() {
        return messageReceiver;
    }

    public static List<String> getKnownSaeIds() {
        return List.copyOf(ADDRESS_BY_SAE_ID.keySet());
    }

    public static List<SaeNode> getKnownSaeNodes() {
        return KNOWN_SAE_NODES;
    }

    public record SaeNode(String saeId, String location) {
        public SaeNode {
            Objects.requireNonNull(saeId, "saeId must not be null");
            Objects.requireNonNull(location, "location must not be null");
        }
    }

    /**
     * Connect to remote node commands over RMI/TLS.
     */
    public NodeCommands connect(Address remoteAddress)
            throws RemoteException, NotBoundException {
        return connect(remoteAddress, COMM_INTERFACE_NAME);
    }

    /**
     * Connects to remote node commands over RMI/TLS using SAE ID lookup from static configuration.
     */
    public NodeCommands connectBySaeId(String remoteSaeId)
            throws RemoteException, NotBoundException {
        Address remoteAddress = getAddressForSaeId(remoteSaeId);
        try {
            return connect(remoteAddress, COMM_INTERFACE_NAME);
        } catch (NotBoundException ex) {
            NotBoundException clarified = new NotBoundException(
                    "Peer SAE '" + remoteSaeId + "' RMI binding not found at "
                            + remoteAddress.hostname + ":" + remoteAddress.port
                            + " — start that node before targeting it"
            );
            clarified.setStackTrace(ex.getStackTrace());
            throw clarified;
        } catch (RemoteException ex) {
            throw new RemoteException(
                    "Peer SAE '" + remoteSaeId + "' unreachable at "
                            + remoteAddress.hostname + ":" + remoteAddress.port
                            + " — is the second node running? (" + ex.getMessage() + ")",
                    ex
            );
        }
    }

    public NodeCommands connect(Address remoteAddress, String bindingName)
            throws RemoteException, NotBoundException {
        Objects.requireNonNull(remoteAddress, "remoteAddress must not be null");
        Objects.requireNonNull(bindingName, "bindingName must not be null");
        requireInstalledTlsContext();

        PqcTlsRmiClientSocketFactory clientFactory = new PqcTlsRmiClientSocketFactory();
        Registry remoteRegistry = LocateRegistry.getRegistry(remoteAddress.hostname, remoteAddress.port, clientFactory);
        return (NodeCommands) remoteRegistry.lookup(bindingName);
    }

    private static SSLContext requireInstalledTlsContext() {
        SSLContext context = installedTlsContext;
        if (context == null) {
            throw new IllegalStateException("RMI TLS context not installed — start RmiManager first");
        }
        return context;
    }

    private static final class PqcTlsRmiClientSocketFactory extends SslRMIClientSocketFactory {
        private static final long serialVersionUID = 1L;

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            return NodeTls.createClientSocket(host, port, requireInstalledTlsContext(), TLS_PROFILE);
        }
    }

    private static final class PqcTlsRmiServerSocketFactory extends SslRMIServerSocketFactory {
        private static final long serialVersionUID = 1L;
        private final boolean needClientAuth;

        private PqcTlsRmiServerSocketFactory(boolean needClientAuth) {
            this.needClientAuth = needClientAuth;
        }

        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return NodeTls.createServerSocket(port, requireInstalledTlsContext(), TLS_PROFILE, needClientAuth);
        }
    }

    private static Address getAddressForSaeId(String saeId) {
        if (saeId == null || saeId.isBlank()) {
            throw new IllegalArgumentException("saeId must not be null or blank");
        }
        Address address = ADDRESS_BY_SAE_ID.get(saeId.trim());
        if (address == null) {
            throw new IllegalArgumentException("Unknown SAE ID: " + saeId);
        }
        return new Address(address);
    }

    private static Map<String, Address> loadSaeNodeAddresses() {
        return loadSaeNodeConfigRows().addresses();
    }

    private static List<SaeNode> loadKnownSaeNodes() {
        return loadSaeNodeConfigRows().nodes();
    }

    private static SaeNodeConfig loadSaeNodeConfigRows() {
        try (InputStream input = RmiManager.class.getResourceAsStream(SAE_NODES_RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("Missing resource: " + SAE_NODES_RESOURCE);
            }

            ObjectMapper mapper = new ObjectMapper();
            SaeNodeConfigRow[] rows = mapper.readValue(input, SaeNodeConfigRow[].class);
            Map<String, Address> addresses = new LinkedHashMap<>();
            List<SaeNode> nodes = new ArrayList<>();

            for (SaeNodeConfigRow row : rows) {
                String saeId = Objects.toString(row.saeId, "").trim();
                String location = Objects.toString(row.location, "").trim();
                String hostname = Objects.toString(row.hostname, "").trim();
                int port = row.port;

                if (saeId.isEmpty() || hostname.isEmpty() || port <= 0 || port > 65535) {
                    throw new IllegalStateException("Invalid row in " + SAE_NODES_RESOURCE + ": " + row);
                }
                if (location.isEmpty()) {
                    location = saeId;
                }
                if (addresses.put(saeId, new Address(hostname, port)) != null) {
                    throw new IllegalStateException("Duplicate saeId in " + SAE_NODES_RESOURCE + ": " + saeId);
                }
                nodes.add(new SaeNode(saeId, location));
            }
            return new SaeNodeConfig(Map.copyOf(addresses), List.copyOf(nodes));
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load SAE node configuration from " + SAE_NODES_RESOURCE, ex);
        }
    }

    private record SaeNodeConfig(Map<String, Address> addresses, List<SaeNode> nodes) {
    }

    private static final class SaeNodeConfigRow {
        public String saeId;
        public String location;
        public String hostname;
        public int port;

        @Override
        public String toString() {
            return "SaeNodeConfigRow{saeId='" + saeId + "', location='" + location
                    + "', hostname='" + hostname + "', port=" + port + "}";
        }
    }
}
