package fel.cvut.terminalapp;

import fel.cvut.terminal.ClientSelector;
import fel.cvut.terminal.LocalOperatorConsole;
import fel.cvut.terminal.OperatorConsole;
import fel.cvut.terminal.TerminalOutput;
import fel.cvut.terminal.TerminalWireProtocol;
import fel.cvut.tls.HsmNodeTls;
import fel.cvut.tls.SoftwareTls;
import fel.cvut.utimaco.Pqmi;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.time.Instant;
import java.util.List;

/**
 * Standalone operator terminal.
 *
 * <p>Connects to a node's dedicated terminal gateway port over TLS using the exact same TLS
 * bootstrap nodes use to talk to each other — {@link SoftwareTls#createContextForNode} (HSM-backed
 * identity via {@link Pqmi}) and {@link SoftwareTls.TlsProfile#PURE_PQC}.
 *
 * <p>Target node and USB path come from {@code NODE_HOSTNAME} / {@code NODE_TERMINAL_PORT}
 * / {@code NODE_NATIVE_PORT} / {@code USB_SERIAL_PORT}.
 *
 * <p>Keeps one long-lived operator-gateway TLS session. It reconnects only after that session
 * ends or the initial TCP/TLS handshake fails (for example when the node is not up yet).
 */
public final class TerminalApp {

    private static final long RETRY_MS = 500;

    private TerminalApp() {
    }

    public static void main(String[] args) throws Exception {
        String tlsNodeId = requireEnv("TLS_NODE_ID");
        String host = requireEnv("NODE_HOSTNAME");
        int port = Integer.parseInt(requireEnv("NODE_TERMINAL_PORT"));

        OperatorConsole console = new LocalOperatorConsole();

        try (Pqmi pqmi = Pqmi.fromEnvironment()) {
            SSLContext ctx = HsmNodeTls.createContextForNode(pqmi, tlsNodeId);
            boolean usbStarted = false;
            while (!Thread.currentThread().isInterrupted()) {
                try (SSLSocket socket = connectGateway(host, port, ctx)) {
                    System.out.println("Operator gateway connected — waiting for node requests.");
                    if (!usbStarted) {
                        maybeStartUsbBridge(host);
                        usbStarted = true;
                    }
                    serve(TerminalWireProtocol.reader(socket.getInputStream()),
                            socket.getOutputStream(), console);
                    System.out.println("Operator gateway session ended.");
                } catch (IOException e) {
                    System.err.println("Operator gateway unavailable: " + e.getMessage());
                }
                if (!sleepRetry()) {
                    return;
                }
            }
        }
    }

    private static SSLSocket connectGateway(String host, int port, SSLContext ctx) throws IOException {
        System.out.println("Connecting to node terminal gateway at " + host + ":" + port + " ...");
        return SoftwareTls.createClientSocket(host, port, ctx, SoftwareTls.TlsProfile.PURE_PQC);
    }

    private static boolean sleepRetry() {
        try {
            Thread.sleep(RETRY_MS);
            return true;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static void maybeStartUsbBridge(String nodeHost) {
        if (!envFlagTrue("USB_BRIDGE")) {
            System.out.println("USB bridge disabled (set USB_BRIDGE=1 for built-in pump, or use socat)");
            return;
        }
        String serialPort = envOrDefault("USB_SERIAL_PORT", UsbTcpBridge.DEFAULT_PORT);
        int baudRate = Integer.parseInt(envOrDefault("USB_BAUD_RATE", "115200"));
        int nativePort = Integer.parseInt(requireEnv("NODE_NATIVE_PORT"));

        UsbTcpBridge bridge = new UsbTcpBridge(serialPort, baudRate);
        Thread bridgeThread = new Thread(
                () -> bridge.run(
                        nodeHost,
                        nativePort,
                        () -> "PROVISION " + Instant.now().getEpochSecond(),
                        () -> TerminalOutput.promptYesNo("Provision another device?")),
                "usb-tcp-bridge");
        bridgeThread.setDaemon(true);
        bridgeThread.start();
        System.out.println("USB redirect enabled: " + serialPort + " -> " + nodeHost + ":" + nativePort
                + " (waiting for device if not present)");
    }

    private static boolean envFlagTrue(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            return false;
        }
        return switch (v.trim().toLowerCase()) {
            case "1", "true", "yes", "on" -> true;
            default -> false;
        };
    }

    private static String envOrDefault(String name, String defaultValue) {
        String v = System.getenv(name);
        return (v == null || v.isBlank()) ? defaultValue : v.trim();
    }

    private static void serve(BufferedReader in, OutputStream out, OperatorConsole console)
            throws IOException {
        while (true) {
            TerminalWireProtocol.Request request;
            try {
                request = TerminalWireProtocol.readRequest(in);
            } catch (IOException e) {
                System.out.println("Node closed the terminal session: " + e.getMessage());
                return;
            }
            TerminalWireProtocol.writeResponse(out, handle(request, console));
        }
    }

    private static TerminalWireProtocol.Response handle(
            TerminalWireProtocol.Request request, OperatorConsole console
    ) throws IOException {
        try {
            return switch (request.type()) {
                case "SELECT" -> {
                    ClientSelector.Selection selection = console.selectTarget(
                            toLabeledOptions(request.clients()), toLabeledOptions(request.saes()));
                    yield TerminalWireProtocol.Response.select(selection.clientId(), selection.saeId());
                }
                case "CONFIRM" -> TerminalWireProtocol.Response.confirm(
                        console.confirmDeletion(request.message()));
                case "NOTIFY" -> {
                    console.showMessage(request.message());
                    yield TerminalWireProtocol.Response.notifyAck();
                }
                default -> throw new IllegalArgumentException(
                        "Unknown terminal request type: " + request.type());
            };
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to handle terminal request: " + request.type(), e);
        }
    }

    private static List<ClientSelector.LabeledOption> toLabeledOptions(
            List<TerminalWireProtocol.Option> options
    ) {
        return options.stream().map(o -> new ClientSelector.LabeledOption(o.id(), o.label())).toList();
    }

    private static String requireEnv(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException("Required environment variable not set: " + name);
        }
        return v.trim();
    }
}
