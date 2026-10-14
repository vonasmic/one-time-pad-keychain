package fel.cvut.node.interNodeCommunication;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.cert.Certificate;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Peer pinning and caller binding for RMI over mTLS.
 *
 * <p>Server side: accepted sockets are wrapped so that the TLS handshake and the pin check run on
 * the RMI connection thread (not in the accept loop). A peer whose leaf is neither the local leaf
 * nor listed in {@link KnownPeers} is disconnected before any RMI byte is read. Every read binds
 * the peer's SAE ID in {@link RmiCallerContext}.
 *
 * <p>Client side: {@link #verifyServer} checks the server leaf after the handshake.
 */
final class RmiPeerPinning {

    private static final Logger LOG = Logger.getLogger(RmiPeerPinning.class.getName());

    private RmiPeerPinning() {
    }

    /**
     * Resolves the pinned SAE ID of the remote end of {@code socket}.
     *
     * @throws SSLPeerUnverifiedException if the handshake failed or the peer is not pinned
     */
    static String resolvePeer(SSLSocket socket, KnownPeers peers) throws SSLPeerUnverifiedException {
        SSLSession session = socket.getSession();
        Certificate[] chain = session.getPeerCertificates();
        if (chain == null || chain.length == 0) {
            throw new SSLPeerUnverifiedException("RMI peer presented no certificate");
        }
        Certificate leaf = chain[0];
        Certificate[] local = session.getLocalCertificates();
        if (local != null && local.length > 0
                && KnownPeers.spkiSha256(local[0]).equals(KnownPeers.spkiSha256(leaf))) {
            return peers.selfSaeId();
        }
        return peers.saeIdFor(leaf).orElseThrow(() -> new SSLPeerUnverifiedException(
                "RMI peer leaf is not pinned (SPKI SHA-256 " + KnownPeers.spkiSha256(leaf) + ")"));
    }

    /** Client-side check; {@code expectedSaeId} may be null when the endpoint maps to no configured SAE. */
    static void verifyServer(SSLSocket socket, KnownPeers peers, String expectedSaeId) throws IOException {
        String actual;
        try {
            actual = resolvePeer(socket, peers);
        } catch (SSLPeerUnverifiedException ex) {
            closeQuietly(socket);
            throw ex;
        }
        if (expectedSaeId != null && !expectedSaeId.equals(actual)) {
            closeQuietly(socket);
            throw new SSLPeerUnverifiedException(
                    "RMI server is pinned as " + actual + " but endpoint belongs to " + expectedSaeId);
        }
    }

    static ServerSocket pinningServerSocket(SSLServerSocket delegate, KnownPeers peers) throws IOException {
        return new PinningServerSocket(delegate, peers);
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // Already failing.
        }
    }

    private static final class PinningServerSocket extends ServerSocket {
        private final SSLServerSocket delegate;
        private final KnownPeers peers;

        PinningServerSocket(SSLServerSocket delegate, KnownPeers peers) throws IOException {
            super();
            this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
            this.peers = Objects.requireNonNull(peers, "peers must not be null");
        }

        @Override
        public Socket accept() throws IOException {
            return new PeerBoundSocket((SSLSocket) delegate.accept(), peers);
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }

        @Override
        public boolean isClosed() {
            return delegate.isClosed();
        }

        @Override
        public boolean isBound() {
            return delegate.isBound();
        }

        @Override
        public int getLocalPort() {
            return delegate.getLocalPort();
        }

        @Override
        public InetAddress getInetAddress() {
            return delegate.getInetAddress();
        }

        @Override
        public SocketAddress getLocalSocketAddress() {
            return delegate.getLocalSocketAddress();
        }

        @Override
        public void setSoTimeout(int timeout) throws SocketException {
            delegate.setSoTimeout(timeout);
        }

        @Override
        public int getSoTimeout() throws IOException {
            return delegate.getSoTimeout();
        }

        @Override
        public String toString() {
            return "Pinning" + delegate;
        }
    }

    /** Delegating socket; only the operations JDK RMI uses on accepted sockets are forwarded. */
    static final class PeerBoundSocket extends Socket {
        private final SSLSocket delegate;
        private final KnownPeers peers;
        private volatile String peerSaeId;
        private InputStream in;

        PeerBoundSocket(SSLSocket delegate, KnownPeers peers) {
            this.delegate = delegate;
            this.peers = peers;
        }

        String peerSaeId() throws IOException {
            String id = peerSaeId;
            if (id == null) {
                synchronized (this) {
                    if (peerSaeId == null) {
                        try {
                            peerSaeId = resolvePeer(delegate, peers);
                        } catch (SSLPeerUnverifiedException ex) {
                            LOG.warning("Rejected RMI connection from " + delegate.getInetAddress()
                                    + ": " + ex.getMessage());
                            closeQuietly(delegate);
                            throw ex;
                        }
                    }
                    id = peerSaeId;
                }
            }
            return id;
        }

        @Override
        public synchronized InputStream getInputStream() throws IOException {
            if (in == null) {
                in = new FilterInputStream(delegate.getInputStream()) {
                    @Override
                    public int read() throws IOException {
                        RmiCallerContext.bind(peerSaeId());
                        return super.read();
                    }

                    @Override
                    public int read(byte[] b, int off, int len) throws IOException {
                        RmiCallerContext.bind(peerSaeId());
                        return super.read(b, off, len);
                    }
                };
            }
            return in;
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            peerSaeId();
            return delegate.getOutputStream();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }

        @Override
        public boolean isClosed() {
            return delegate.isClosed();
        }

        @Override
        public boolean isConnected() {
            return delegate.isConnected();
        }

        @Override
        public boolean isBound() {
            return delegate.isBound();
        }

        @Override
        public boolean isInputShutdown() {
            return delegate.isInputShutdown();
        }

        @Override
        public boolean isOutputShutdown() {
            return delegate.isOutputShutdown();
        }

        @Override
        public void shutdownInput() throws IOException {
            delegate.shutdownInput();
        }

        @Override
        public void shutdownOutput() throws IOException {
            delegate.shutdownOutput();
        }

        @Override
        public InetAddress getInetAddress() {
            return delegate.getInetAddress();
        }

        @Override
        public InetAddress getLocalAddress() {
            return delegate.getLocalAddress();
        }

        @Override
        public int getPort() {
            return delegate.getPort();
        }

        @Override
        public int getLocalPort() {
            return delegate.getLocalPort();
        }

        @Override
        public SocketAddress getRemoteSocketAddress() {
            return delegate.getRemoteSocketAddress();
        }

        @Override
        public SocketAddress getLocalSocketAddress() {
            return delegate.getLocalSocketAddress();
        }

        @Override
        public void setTcpNoDelay(boolean on) throws SocketException {
            delegate.setTcpNoDelay(on);
        }

        @Override
        public boolean getTcpNoDelay() throws SocketException {
            return delegate.getTcpNoDelay();
        }

        @Override
        public void setKeepAlive(boolean on) throws SocketException {
            delegate.setKeepAlive(on);
        }

        @Override
        public boolean getKeepAlive() throws SocketException {
            return delegate.getKeepAlive();
        }

        @Override
        public void setSoTimeout(int timeout) throws SocketException {
            delegate.setSoTimeout(timeout);
        }

        @Override
        public int getSoTimeout() throws SocketException {
            return delegate.getSoTimeout();
        }

        @Override
        public void setSoLinger(boolean on, int linger) throws SocketException {
            delegate.setSoLinger(on, linger);
        }

        @Override
        public int getSoLinger() throws SocketException {
            return delegate.getSoLinger();
        }

        @Override
        public String toString() {
            return "PeerBound" + delegate;
        }
    }
}
