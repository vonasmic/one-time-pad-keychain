package fel.cvut.node.interNodeCommunication;

import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.bouncyCastle.BouncyCastleTLS;
import fel.cvut.node.Address;

import fel.cvut.node.NodeCommands;
import java.io.InputStream;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
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
 * Manages RMI lifecycle for node-to-node communication with purePQC TLS (ML-DSA + hybrid KEM, TLS 1.3).
 */
public class RmiManager {

    public static final String COMM_INTERFACE_NAME = "NodeCommands";
    private static final String SAE_NODES_RESOURCE = "/sae-nodes.json";
    private static final BouncyCastleTLS.TlsPolicy TLS_POLICY = BouncyCastleTLS.TlsPolicy.purePqc();
    private static final Map<String, Address> ADDRESS_BY_SAE_ID = loadSaeNodeAddresses();
    private static final List<SaeNode> KNOWN_SAE_NODES = loadKnownSaeNodes();

    private final Address myAddress;
    private final String localTlsNodeId;

    private Registry registry;
    private NodeCommands messageReceiver;
    private boolean running = false;

    public RmiManager(Address myAddress, String localTlsNodeId) {
        this.myAddress = Objects.requireNonNull(myAddress, "myAddress must not be null");
        this.localTlsNodeId = Objects.requireNonNull(localTlsNodeId, "localTlsNodeId must not be null");
    }

    /**
     * Start exporting node commands over RMI/TLS.
     */
    public synchronized void start(NodeCommands receiver) {
        if (running) {
            return;
        }

        System.setProperty("java.rmi.server.hostname", myAddress.hostname);
        try {
            this.messageReceiver = Objects.requireNonNull(receiver, "receiver must not be null");

            PqcTlsRmiClientSocketFactory clientFactory = new PqcTlsRmiClientSocketFactory(localTlsNodeId);
            PqcTlsRmiServerSocketFactory serverFactory = new PqcTlsRmiServerSocketFactory(localTlsNodeId, true);

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
    public static NodeCommands connect(Address remoteAddress, String localTlsNodeId)
            throws RemoteException, NotBoundException {
        return connect(remoteAddress, localTlsNodeId, COMM_INTERFACE_NAME);
    }

    /**
     * Connects to remote node commands over RMI/TLS using SAE ID lookup from static configuration.
     */
    public static NodeCommands connectBySaeId(String remoteSaeId, String localTlsNodeId)
            throws RemoteException, NotBoundException {
        Address remoteAddress = getAddressForSaeId(remoteSaeId);
        return connect(remoteAddress, localTlsNodeId, COMM_INTERFACE_NAME);
    }

    public static NodeCommands connect(Address remoteAddress, String localTlsNodeId, String bindingName)
            throws RemoteException, NotBoundException {
        Objects.requireNonNull(remoteAddress, "remoteAddress must not be null");
        Objects.requireNonNull(localTlsNodeId, "localTlsNodeId must not be null");
        Objects.requireNonNull(bindingName, "bindingName must not be null");

        PqcTlsRmiClientSocketFactory clientFactory = new PqcTlsRmiClientSocketFactory(localTlsNodeId);
        Registry remoteRegistry = LocateRegistry.getRegistry(remoteAddress.hostname, remoteAddress.port, clientFactory);
        return (NodeCommands) remoteRegistry.lookup(bindingName);
    }

    private static final class PqcTlsRmiClientSocketFactory extends SslRMIClientSocketFactory {
        private final String localTlsNodeId;

        private PqcTlsRmiClientSocketFactory(String localTlsNodeId) {
            this.localTlsNodeId = Objects.requireNonNull(localTlsNodeId, "localTlsNodeId must not be null");
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            SSLContext context = loadContext(localTlsNodeId);
            SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(host, port);
            SSLParameters params = socket.getSSLParameters();
            BouncyCastleTLS.applyTlsPolicy(params, TLS_POLICY);
            socket.setSSLParameters(params);
            socket.startHandshake();
            return socket;
        }
    }

    private static final class PqcTlsRmiServerSocketFactory extends SslRMIServerSocketFactory {
        private final String localTlsNodeId;
        private final boolean needClientAuth;

        private PqcTlsRmiServerSocketFactory(String localTlsNodeId, boolean needClientAuth) {
            this.localTlsNodeId = Objects.requireNonNull(localTlsNodeId, "localTlsNodeId must not be null");
            this.needClientAuth = needClientAuth;
        }

        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            SSLContext context = loadContext(localTlsNodeId);
            SSLServerSocket serverSocket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(port);
            serverSocket.setNeedClientAuth(needClientAuth);
            SSLParameters params = serverSocket.getSSLParameters();
            BouncyCastleTLS.applyTlsPolicy(params, TLS_POLICY);
            serverSocket.setSSLParameters(params);
            return serverSocket;
        }
    }

    private static SSLContext loadContext(String tlsNodeId) throws IOException {
        try {
            return BouncyCastleTLS.loadContextForNode(tlsNodeId);
        } catch (Exception e) {
            throw new IOException("Failed to load PQC TLS context for node: " + tlsNodeId, e);
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
