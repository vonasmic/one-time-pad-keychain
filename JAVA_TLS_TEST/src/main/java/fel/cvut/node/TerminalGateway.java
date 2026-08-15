package fel.cvut.node;

import fel.cvut.terminal.ClientSelector;
import fel.cvut.terminal.OperatorConsole;
import fel.cvut.terminal.TerminalWireProtocol;
import fel.cvut.tls.NodeTls;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Dedicated TLS endpoint the standalone terminal app connects to for operator interaction
 * (target selection, deletion confirmation, status messages).
 *
 * <p>Reuses the exact TLS bootstrap nodes use to talk to each other — {@link NodeTls#createServerSocket}
 * with {@link NodeTls.TlsProfile#PURE_PQC} on the node's own {@code tlsContext} — so the terminal
 * app authenticates the same way any other node would, instead of a separate ad hoc TLS setup.
 *
 * <p>Only one terminal session is served at a time; a new connection replaces the previous one.
 * Requests are serialized with {@link #requestLock} since {@link Node} may be handling several
 * concurrent client connections that each need operator input.
 */
final class TerminalGateway implements OperatorConsole, AutoCloseable {

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
        gatewayServer = NodeTls.createServerSocket(port, tlsContext, NodeTls.TlsProfile.PURE_PQC, true);
        running = true;
        executor.submit(this::acceptLoop);
    }

    private void acceptLoop() {
        while (running) {
            SSLServerSocket localServer = gatewayServer;
            if (localServer == null) {
                return;
            }
            try {
                SSLSocket socket = (SSLSocket) localServer.accept();
                socket.startHandshake();
                adoptSession(socket);
            } catch (IOException ex) {
                if (running) {
                    System.err.println("Terminal gateway accept loop failed: " + ex.getMessage());
                }
                return;
            }
        }
    }

    private void adoptSession(SSLSocket socket) throws IOException {
        synchronized (sessionLock) {
            closeSessionQuietly();
            session = socket;
            sessionIn = TerminalWireProtocol.reader(socket.getInputStream());
            sessionOut = socket.getOutputStream();
            System.out.println("Terminal app connected: " + socket.getRemoteSocketAddress());
        }
    }

    @Override
    public ClientSelector.Selection selectTarget(
            List<ClientSelector.LabeledOption> clients, List<ClientSelector.LabeledOption> saes
    ) throws Exception {
        TerminalWireProtocol.Response response = exchange(
                TerminalWireProtocol.Request.select(toOptions(clients), toOptions(saes)));
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

    private static List<TerminalWireProtocol.Option> toOptions(List<ClientSelector.LabeledOption> options) {
        return options.stream().map(o -> new TerminalWireProtocol.Option(o.id(), o.label())).toList();
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
                System.err.println("Terminal gateway close failed: " + ex.getMessage());
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
