package fel.cvut.node;

import fel.cvut.terminal.ClientSelector;
import fel.cvut.terminal.OperatorConsole;
import fel.cvut.terminal.TerminalWireProtocol;
import fel.cvut.tls.SoftwareTls;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * Dedicated TLS endpoint the standalone terminal app connects to for operator interaction
 * (target selection, deletion confirmation, status messages).
 *
 * <p>Reuses the exact TLS bootstrap nodes use to talk to each other — {@link SoftwareTls#createServerSocket}
 * with {@link SoftwareTls.TlsProfile#PURE_PQC} on the node's own {@code tlsContext} — so the terminal
 * app authenticates the same way any other node would, instead of a separate ad hoc TLS setup.
 *
 * <p>Only one terminal session is served at a time. While that session is still open, further
 * TCP connects are closed before the TLS handshake so a second client cannot kick the first
 * off the gateway and cannot force an HSM identity signature. A session whose peer has already
 * gone away (lab owner switch restarts the terminal JVM; the gateway does not notice until it
 * reads) is dropped and the new connection is adopted.
 *
 * <p>Requests are serialized with {@link #requestLock} since {@link Node} may be handling several
 * concurrent client connections that each need operator input.
 */
final class TerminalGateway implements OperatorConsole, AutoCloseable {

    private static final Logger LOG = Logger.getLogger(TerminalGateway.class.getName());

    /** Idle read used only to tell a live terminal from one that already closed. */
    private static final int PEER_PROBE_MS = 100;

    private final int port;
    private final ReentrantLock requestLock = new ReentrantLock();
    private final Object sessionLock = new Object();

    private volatile SSLServerSocket gatewayServer;
    private volatile boolean running;
    private SSLSocket session;
    private BufferedReader sessionIn;
    private OutputStream sessionOut;

    TerminalGateway(int port) {
        this.port = port;
    }

    void start(SSLContext tlsContext, ExecutorService executor) throws IOException {
        gatewayServer = SoftwareTls.createServerSocket(port, tlsContext, SoftwareTls.TlsProfile.PURE_PQC, true);
        running = true;
        executor.submit(this::acceptLoop);
    }

    private void acceptLoop() {
        while (running) {
            SSLServerSocket localServer = gatewayServer;
            if (localServer == null) {
                return;
            }
            SSLSocket socket;
            try {
                socket = (SSLSocket) localServer.accept();
            } catch (IOException ex) {
                if (running) {
                    LOG.warning("Terminal gateway accept loop failed: " + ex.getMessage());
                }
                return;
            }
            try {
                if (heldByLivePeer()) {
                    LOG.info("Terminal app already connected — rejecting "
                            + socket.getRemoteSocketAddress());
                    socket.close();
                    continue;
                }
                socket.startHandshake();
                adoptSession(socket);
            } catch (IOException ex) {
                LOG.warning("Terminal gateway connection failed: " + ex.getMessage());
                try {
                    socket.close();
                } catch (IOException ignored) {
                    /* client already gone */
                }
            }
        }
    }

    /**
     * {@code SSLSocket#isConnected()} stays true after the terminal process exits, until this
     * side reads. Probe under {@link #requestLock} so the check cannot consume a response
     * {@link #exchange} is waiting for.
     */
    private boolean heldByLivePeer() {
        requestLock.lock();
        try {
            synchronized (sessionLock) {
                if (!sessionLive()) {
                    return false;
                }
                if (peerClosed()) {
                    LOG.info("Terminal session ended — accepting a new connection");
                    closeSessionQuietly();
                    return false;
                }
                return true;
            }
        } finally {
            requestLock.unlock();
        }
    }

    private boolean peerClosed() {
        SSLSocket current = session;
        BufferedReader in = sessionIn;
        if (current == null || in == null) {
            return true;
        }
        int previousTimeout;
        try {
            previousTimeout = current.getSoTimeout();
            current.setSoTimeout(PEER_PROBE_MS);
        } catch (IOException e) {
            return true;
        }
        try {
            in.mark(8192);
            int ch = in.read();
            if (ch < 0) {
                return true;
            }
            in.reset();
            return false;
        } catch (SocketTimeoutException e) {
            return false;
        } catch (IOException e) {
            return !isTimeout(e);
        } finally {
            try {
                current.setSoTimeout(previousTimeout);
            } catch (IOException ignored) {
                /* socket already unusable; caller drops it when peerClosed is true */
            }
        }
    }

    private static boolean isTimeout(IOException e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof SocketTimeoutException) {
                return true;
            }
        }
        String msg = e.getMessage();
        return msg != null && msg.toLowerCase(Locale.ROOT).contains("timed out");
    }

    private void adoptSession(SSLSocket socket) throws IOException {
        synchronized (sessionLock) {
            closeSessionQuietly();
            session = socket;
            sessionIn = TerminalWireProtocol.reader(socket.getInputStream());
            sessionOut = socket.getOutputStream();
            LOG.info("Terminal app connected: " + socket.getRemoteSocketAddress());
        }
    }

    private boolean sessionLive() {
        return session != null && session.isConnected() && !session.isClosed();
    }

    @Override
    public ClientSelector.Selection selectTarget(
            List<ClientSelector.LabeledOption> clients, List<ClientSelector.LabeledOption> saes
    ) throws Exception {
        TerminalWireProtocol.Response response = exchange(
                TerminalWireProtocol.Request.select(clients, saes));
        return new ClientSelector.Selection(response.clientId(), response.saeId());
    }

    @Override
    public boolean confirmDeletion(String message) throws Exception {
        return exchange(TerminalWireProtocol.Request.confirm(message)).confirmed();
    }

    @Override
    public void showMessage(String message) throws Exception {
        exchange(TerminalWireProtocol.Request.notify(message));
    }

    private TerminalWireProtocol.Response exchange(TerminalWireProtocol.Request request) throws IOException {
        requestLock.lock();
        try {
            BufferedReader in;
            OutputStream out;
            synchronized (sessionLock) {
                if (session == null) {
                    throw new IllegalStateException(
                            "No terminal app connected on port " + port + " — start the terminal app first.");
                }
                in = sessionIn;
                out = sessionOut;
            }
            TerminalWireProtocol.writeRequest(out, request);
            return TerminalWireProtocol.readResponse(in);
        } finally {
            requestLock.unlock();
        }
    }

    @Override
    public void close() {
        running = false;
        synchronized (sessionLock) {
            closeSessionQuietly();
        }
        SSLServerSocket localServer = gatewayServer;
        gatewayServer = null;
        if (localServer != null) {
            try {
                localServer.close();
            } catch (IOException ex) {
                LOG.warning("Terminal gateway close failed: " + ex.getMessage());
            }
        }
    }

    private void closeSessionQuietly() {
        if (session != null) {
            try {
                session.close();
            } catch (IOException ignored) {
            }
        }
        session = null;
        sessionIn = null;
        sessionOut = null;
    }
}
