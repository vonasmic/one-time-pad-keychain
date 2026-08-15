package fel.cvut.terminalapp;

import fel.cvut.terminal.ClientSelector;
import fel.cvut.terminal.LocalOperatorConsole;
import fel.cvut.terminal.OperatorConsole;
import fel.cvut.terminal.TerminalWireProtocol;
import fel.cvut.tls.NodeTls;
import fel.cvut.utimaco.Pqmi;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * Standalone operator terminal.
 *
 * <p>Connects to a node's dedicated terminal gateway port over TLS using the exact same TLS
 * bootstrap nodes use to talk to each other — {@link NodeTls#createContextForNode} (HSM-backed
 * identity via {@link Pqmi}) and {@link NodeTls.TlsProfile#PURE_PQC} — so the terminal app is
 * authenticated like any other node instead of a bespoke client TLS setup. Once connected, it
 * answers SELECT / CONFIRM / NOTIFY requests locally via stdin ({@link LocalOperatorConsole}) until the
 * node closes the session.
 *
 * <p>Required environment variables:
 * <ul>
 *   <li>{@code TLS_NODE_ID} – HSM identity used to authenticate to the node
 *       ({@code certs/{TLS_NODE_ID}.pem} + HSM key; provision via {@code CertGenerator})</li>
 *   <li>{@code NODE_HOSTNAME} – hostname of the node to connect to</li>
 *   <li>{@code NODE_TERMINAL_PORT} – the node's terminal gateway port</li>
 * </ul>
 *
 * <p>HSM connection ({@code HSM_DEVICE}, {@code HSM_USER}, {@code HSM_PIN}, …) comes from
 * {@code env/hsm.env}, same as for a node.
 *
 * <p>USB↔TCP for the embedded device is optional and independent of the operator console.
 * Set {@code USB_BRIDGE=1} (and {@code NODE_NATIVE_PORT}) to use the built-in opaque pump, or
 * leave it off and run {@code socat} yourself:
 * <pre>{@code
 * socat -d -d /dev/ttyACM0,b115200,raw,echo=0,crtscts=0 TCP:127.0.0.1:11111
 * }</pre>
 * Optional: {@code USB_SERIAL_PORT} (default {@code /dev/ttyACM0}), {@code USB_BAUD_RATE}
 * (default {@code 115200}).
 */
public final class TerminalApp {

    private TerminalApp() {
    }

    public static void main(String[] args) throws Exception {
        String tlsNodeId = requireEnv("TLS_NODE_ID");
        String host = requireEnv("NODE_HOSTNAME");
        int port = Integer.parseInt(requireEnv("NODE_TERMINAL_PORT"));

        OperatorConsole console = new LocalOperatorConsole();
        maybeStartUsbBridge(host);

        try (Pqmi pqmi = Pqmi.fromEnvironment()) {
            SSLContext ctx = NodeTls.createContextForNode(pqmi, tlsNodeId);
            while (!Thread.currentThread().isInterrupted()) {
                System.out.println("Connecting to node terminal gateway at " + host + ":" + port + " ...");
                try (SSLSocket socket = NodeTls.createClientSocket(host, port, ctx, NodeTls.TlsProfile.PURE_PQC)) {
                    System.out.println("Connected. Waiting for operator requests.");
                    serve(TerminalWireProtocol.reader(socket.getInputStream()), socket.getOutputStream(), console);
                } catch (IOException e) {
                    System.err.println("TLS connection failed: " + e.getMessage() + " — retrying in 5 seconds");
                    try {
                        Thread.sleep(5_000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
        }
    }

    /**
     * Optional opaque USB↔TCP pump. Prefer {@code socat} for the same job; enable this only with
     * {@code USB_BRIDGE=1}.
     */
    private static void maybeStartUsbBridge(String nodeHost) {
        if (!envFlagTrue("USB_BRIDGE")) {
            System.out.println("USB bridge disabled (set USB_BRIDGE=1 for built-in pump, or use socat)");
            return;
        }
        String serialPort = envOrDefault("USB_SERIAL_PORT", UsbTcpBridge.DEFAULT_PORT);
        int baudRate = Integer.parseInt(envOrDefault("USB_BAUD_RATE", "115200"));
        int nativePort = Integer.parseInt(requireEnv("NODE_NATIVE_PORT"));

        UsbTcpBridge bridge = new UsbTcpBridge(serialPort, baudRate, nodeHost, nativePort);
        Thread bridgeThread = new Thread(bridge::run, "usb-tcp-bridge");
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

    private static void serve(BufferedReader in, OutputStream out, OperatorConsole console) throws IOException {
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

    private static TerminalWireProtocol.Response handle(TerminalWireProtocol.Request request, OperatorConsole console)
            throws IOException {
        try {
            return switch (request.type()) {
                case "SELECT" -> {
                    ClientSelector.Selection selection = console.selectTarget(
                            toLabeledOptions(request.clients()), toLabeledOptions(request.saes()));
                    yield TerminalWireProtocol.Response.select(selection.clientId(), selection.saeId());
                }
                case "CONFIRM" -> TerminalWireProtocol.Response.confirm(console.confirmDeletion(request.message()));
                case "NOTIFY" -> {
                    console.showMessage(request.message());
                    yield TerminalWireProtocol.Response.notifyAck();
                }
                default -> throw new IllegalArgumentException("Unknown terminal request type: " + request.type());
            };
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to handle terminal request: " + request.type(), e);
        }
    }

    private static List<ClientSelector.LabeledOption> toLabeledOptions(List<TerminalWireProtocol.Option> options) {
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
