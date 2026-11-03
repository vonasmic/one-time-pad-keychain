package fel.cvut.node.interNodeCommunication;

import fel.cvut.tls.SoftwareTls;
import fel.cvut.node.Address;

import fel.cvut.node.NodeCommands;
import javax.net.ssl.SSLContext;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;
import java.io.IOException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Manages RMI lifecycle for node-to-node communication with pure PQC TLS (ML-DSA + ML-KEM, TLS 1.3).
 */
public class RmiManager {

    public static final String COMM_INTERFACE_NAME = "NodeCommands";
    private static final SoftwareTls.TlsProfile TLS_PROFILE = SoftwareTls.TlsProfile.PURE_PQC;

    /** Env: local address the RMI registry and object port bind to (default: own directory entry's hostname). */
    public static final String ENV_BIND = "NODE_RMI_BIND";
    private static final int OBJECT_PORT_OFFSET = 40000;

    /** JVM-local TLS context for RMI sockets — must not be stored on serializable socket factories. */
    private static volatile SSLContext installedTlsContext;
    /** JVM-local pinned peers and SAE directory, same lifecycle as {@link #installedTlsContext}. */
    private static volatile KnownPeers installedKnownPeers;
    private static volatile SaeNodes installedSaeNodes;

    private final Address myAddress;
    private final String bindHost;
    private final SaeNodes saeNodes;
    private final String selfSaeId;
    private final KnownPeers knownPeers;

    private Registry registry;
    private NodeCommands messageReceiver;
    private boolean running = false;

    /** Manager without an SAE directory: can be constructed and queried, but {@link #start} refuses to run. */
    public RmiManager(Address myAddress) {
        this(myAddress, null, null, null);
    }

    /**
     * @param bindHost  local address for the registry and object port; {@code null} uses
     *                  {@code myAddress.hostname}
     * @param selfSaeId local SAE ID, bound as the caller for the node's own leaf
     * @param saeNodes  SAE directory with the peer pins; {@code null} makes {@link #start} fail closed
     */
    public RmiManager(Address myAddress, String bindHost, String selfSaeId, SaeNodes saeNodes) {
        this.myAddress = Objects.requireNonNull(myAddress, "myAddress must not be null");
        this.bindHost = bindHost == null || bindHost.isBlank() ? myAddress.hostname : bindHost.trim();
        this.saeNodes = saeNodes == null ? SaeNodes.of(List.of()) : saeNodes;
        this.selfSaeId = selfSaeId;
        this.knownPeers = saeNodes == null ? null : KnownPeers.from(selfSaeId, saeNodes);
    }

    /**
     * Production wiring: the advertised address (hostname and registry port) is the own entry of
     * {@code directory}; {@value #ENV_BIND} optionally names the local bind address.
     */
    public static RmiManager forSelf(SaeNodes directory, String saeId) {
        return forSelf(directory, saeId, System.getenv(ENV_BIND));
    }

    public static RmiManager forSelf(SaeNodes directory, String saeId, String bindHost) {
        Objects.requireNonNull(directory, "directory must not be null");
        SaeNodes.Entry self = directory.self(saeId);
        return new RmiManager(self.address(), bindHost, self.saeId(), directory);
    }

    /** Own entry of the SAE directory. */
    public SaeNodes.Entry selfEntry() {
        return saeNodes.self(selfSaeId);
    }

    /** Advertised RMI registry address. */
    public Address address() {
        return new Address(myAddress);
    }

    /** Effective bind address (for diagnostics and tests). */
    public String bindHost() {
        return bindHost;
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
            if (knownPeers == null) {
                throw new IllegalStateException("RMI peer pinning is not configured (" + SaeNodes.ENV_FILE + ")");
            }
            installedKnownPeers = knownPeers;
            installedSaeNodes = saeNodes;
            RmiSerialFilter.installForReplies();
            InetAddress bindAddress = InetAddress.getByName(bindHost);

            PqcTlsRmiClientSocketFactory clientFactory = new PqcTlsRmiClientSocketFactory();
            PqcTlsRmiServerSocketFactory serverFactory = new PqcTlsRmiServerSocketFactory(true, bindAddress);

            NodeCommands skeleton = (NodeCommands) UnicastRemoteObject.exportObject(
                    messageReceiver,
                    OBJECT_PORT_OFFSET + myAddress.port,
                    clientFactory,
                    serverFactory,
                    RmiSerialFilter.CALLS
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
            installedKnownPeers = null;
            installedSaeNodes = null;
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
        installedKnownPeers = null;
        installedSaeNodes = null;
        running = false;
    }

    public boolean isRunning() {
        return running;
    }

    public NodeCommands getMessageReceiver() {
        return messageReceiver;
    }

    public List<String> getKnownSaeIds() {
        return saeNodes.entries().stream().map(SaeNodes.Entry::saeId).toList();
    }

    /** SAE IDs and locations from the SAE directory, for operator menus. */
    public List<SaeNode> getKnownSaeNodes() {
        return saeNodes.entries().stream().map(e -> new SaeNode(e.saeId(), e.location())).toList();
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
     * Connects to remote node commands over RMI/TLS using the address from the SAE directory.
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

    private static KnownPeers requireInstalledKnownPeers() {
        KnownPeers peers = installedKnownPeers;
        if (peers == null) {
            throw new IllegalStateException("RMI peer pins not installed — start RmiManager first");
        }
        return peers;
    }

    /** SAE whose configured registry or object endpoint is {@code host:port}, or null. */
    static String expectedSaeIdFor(SaeNodes nodes, String host, int port) {
        for (SaeNodes.Entry e : nodes.entries()) {
            Address a = e.address();
            if (a.hostname.equals(host) && (a.port == port || a.port + OBJECT_PORT_OFFSET == port)) {
                return e.saeId();
            }
        }
        return null;
    }

    private static SaeNodes requireInstalledSaeNodes() {
        SaeNodes nodes = installedSaeNodes;
        if (nodes == null) {
            throw new IllegalStateException("SAE directory not installed — start RmiManager first");
        }
        return nodes;
    }

    private static final class PqcTlsRmiClientSocketFactory extends SslRMIClientSocketFactory {
        private static final long serialVersionUID = 1L;

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            KnownPeers peers = requireInstalledKnownPeers();
            SSLSocket socket = SoftwareTls.createClientSocket(host, port, requireInstalledTlsContext(), TLS_PROFILE);
            RmiPeerPinning.verifyServer(socket, peers, expectedSaeIdFor(requireInstalledSaeNodes(), host, port));
            return socket;
        }
    }

    private static final class PqcTlsRmiServerSocketFactory extends SslRMIServerSocketFactory {
        private static final long serialVersionUID = 2L;
        private final boolean needClientAuth;
        private final InetAddress bindAddress;

        private PqcTlsRmiServerSocketFactory(boolean needClientAuth, InetAddress bindAddress) {
            this.needClientAuth = needClientAuth;
            this.bindAddress = Objects.requireNonNull(bindAddress, "bindAddress must not be null");
        }

        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            SSLServerSocket tls = SoftwareTls.createServerSocket(
                    port, requireInstalledTlsContext(), TLS_PROFILE, needClientAuth, bindAddress);
            return RmiPeerPinning.pinningServerSocket(tls, requireInstalledKnownPeers());
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof PqcTlsRmiServerSocketFactory f
                    && f.needClientAuth == needClientAuth && f.bindAddress.equals(bindAddress);
        }

        @Override
        public int hashCode() {
            return Objects.hash(needClientAuth, bindAddress);
        }
    }

    private Address getAddressForSaeId(String saeId) {
        if (saeId == null || saeId.isBlank()) {
            throw new IllegalArgumentException("saeId must not be null or blank");
        }
        return saeNodes.find(saeId)
                .map(e -> new Address(e.address()))
                .orElseThrow(() -> new IllegalArgumentException("Unknown SAE ID: " + saeId));
    }
}
