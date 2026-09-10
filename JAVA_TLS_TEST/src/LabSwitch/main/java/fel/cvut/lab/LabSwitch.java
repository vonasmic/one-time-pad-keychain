package fel.cvut.lab;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.UnaryOperator;

/**
 * Lab-only shared switch file: USB owner ({@code USER} / {@code SAE}) is independent
 * of which client (keychain + SAE node) is selected. CL 1 is SAE 1; CL 2 is SAE 2.
 *
 * <p>{@link LabSwitchApp} writes this file. {@code scripts/lab-run.py} reads it and
 * restarts TerminalApp / UserApp in the same tmux pane with {@code USB_SERIAL_PORT}
 * / {@code NODE_*} rewritten. Production Java does not import this package.
 *
 * <p>Production never sets {@code USB_LAB_FILE}. Delete this package to drop the helper.
 */
public final class LabSwitch {

    public static final String MODE_USER = "USER";
    public static final String MODE_SAE = "SAE";
    public static final String ID_CLIENT1 = "client-1";
    public static final String ID_CLIENT2 = "client-2";
    public static final String DEFAULT_SERIAL_CLIENT1 = "/tmp/ttyACM-se1";
    public static final String DEFAULT_SERIAL_CLIENT2 = "/tmp/ttyACM-se2";
    public static final Path DEFAULT_PATH = Path.of("/tmp/otp-keychain-lab.json");

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);
    private static final ConcurrentHashMap<String, LabSwitch> INSTANCES = new ConcurrentHashMap<>();

    private enum Kind {
        OWNER,
        CLIENT
    }

    private record Parsed(Kind kind, String value) {
    }

    private final Path path;
    private final FileChannel channel;

    private LabSwitch(Path path) {
        this.path = path;
        try {
            Path parent = path.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            this.channel = FileChannel.open(
                    path,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.READ,
                    StandardOpenOption.WRITE);
        } catch (IOException e) {
            throw new IllegalStateException("Lab switch file " + path + ": " + e.getMessage(), e);
        }
        update(s -> s);
    }

    public static LabSwitch open(Path path) {
        Objects.requireNonNull(path, "path");
        Path normalized = path.toAbsolutePath().normalize();
        return INSTANCES.computeIfAbsent(normalized.toString(), ignored -> new LabSwitch(normalized));
    }

    public Path path() {
        return path;
    }

    public State read() {
        return update(s -> s);
    }

    /**
     * Apply a CLI token: {@code USER}/{@code SAE} change owner only;
     * {@code CL 1}/{@code CL 2} (and {@code SAE 1}/{@code SAE 2}) change client only.
     */
    public State apply(String command) {
        Parsed parsed = parseCommand(command);
        return update(s -> parsed.kind() == Kind.OWNER
                ? s.withOwner(parsed.value())
                : s.withClient(parsed.value()));
    }

    /** Same as {@link #apply(String)}. */
    public State setMode(String command) {
        return apply(command);
    }

    private synchronized State update(UnaryOperator<State> op) {
        try {
            FileLock lock = channel.lock();
            try {
                State cur = parse(channel);
                State next = defaults(op.apply(cur));
                if (!next.equals(cur) || channel.size() == 0L) {
                    write(channel, next);
                }
                return next;
            } finally {
                lock.release();
            }
        } catch (IOException e) {
            throw new IllegalStateException("Lab switch file " + path + ": " + e.getMessage(), e);
        }
    }

    private static State parse(FileChannel ch) throws IOException {
        if (ch.size() == 0L) {
            return defaults(null);
        }
        ByteBuffer buf = ByteBuffer.allocate((int) Math.min(ch.size(), 1_000_000L));
        ch.position(0);
        ch.read(buf);
        String json = new String(buf.array(), 0, buf.position(), StandardCharsets.UTF_8).strip();
        if (json.isEmpty()) {
            return defaults(null);
        }
        try {
            return defaults(MAPPER.readValue(json, State.class));
        } catch (IOException e) {
            return defaults(null);
        }
    }

    private static void write(FileChannel ch, State state) throws IOException {
        byte[] bytes = MAPPER.writeValueAsBytes(state);
        ch.truncate(0);
        ch.position(0);
        ch.write(ByteBuffer.wrap(bytes));
        ch.force(true);
    }

    private static State defaults(State raw) {
        Map<String, Node> incoming = raw == null ? Map.of() : raw.nodes();
        Map<String, Node> nodes = new LinkedHashMap<>();
        nodes.put(ID_CLIENT1, completeNode(
                firstNode(incoming, ID_CLIENT1, "sae-1"),
                "127.0.0.1", 11111, 11112, DEFAULT_SERIAL_CLIENT1));
        nodes.put(ID_CLIENT2, completeNode(
                firstNode(incoming, ID_CLIENT2, "sae-2"),
                "127.0.0.1", 5020, 11113, DEFAULT_SERIAL_CLIENT2));
        if (raw == null) {
            return new State(MODE_USER, ID_CLIENT1, nodes);
        }
        String token = raw.mode() == null ? "" : token(raw.mode());
        String mode;
        String client;
        switch (token) {
            case "CLIENT1", "CLIENT 1", "CL1", "CL 1", "C1", "SAE1", "SAE 1" -> {
                mode = MODE_SAE;
                client = ID_CLIENT1;
            }
            case "CLIENT2", "CLIENT 2", "CL2", "CL 2", "C2", "SAE2", "SAE 2" -> {
                mode = MODE_SAE;
                client = ID_CLIENT2;
            }
            case "SAE", "TERM", "TERMINAL", "T" -> {
                mode = MODE_SAE;
                client = blank(raw.client()) ? ID_CLIENT1 : normalizeClient(raw.client());
            }
            default -> {
                mode = MODE_USER;
                client = blank(raw.client()) ? ID_CLIENT1 : normalizeClient(raw.client());
            }
        }
        return new State(mode, client, nodes);
    }

    private static Node firstNode(Map<String, Node> nodes, String... ids) {
        if (nodes == null || nodes.isEmpty()) {
            return null;
        }
        for (String id : ids) {
            Node n = nodes.get(id);
            if (n != null) {
                return n;
            }
        }
        return null;
    }

    private static Node completeNode(
            Node raw, String host, int nativePort, int terminalPort, String serial
    ) {
        if (raw == null) {
            return new Node(host, nativePort, terminalPort, serial);
        }
        String h = raw.host() == null || raw.host().isBlank() ? host : raw.host().trim();
        int n = raw.nativePort() == 0 ? nativePort : raw.nativePort();
        int t = raw.terminalPort() == 0 ? terminalPort : raw.terminalPort();
        String s = raw.serialPort() == null || raw.serialPort().isBlank() ? serial : raw.serialPort().trim();
        return new Node(h, n, t, s);
    }

    private static Parsed parseCommand(String command) {
        Objects.requireNonNull(command, "command");
        String m = token(command);
        return switch (m) {
            case "USER", "U", "HOME" -> new Parsed(Kind.OWNER, MODE_USER);
            case "SAE", "TERM", "TERMINAL", "T" -> new Parsed(Kind.OWNER, MODE_SAE);
            case "CLIENT1", "CLIENT 1", "CL1", "CL 1", "C1", "1", "SAE1", "SAE 1" ->
                    new Parsed(Kind.CLIENT, ID_CLIENT1);
            case "CLIENT2", "CLIENT 2", "CL2", "CL 2", "C2", "2", "SAE2", "SAE 2" ->
                    new Parsed(Kind.CLIENT, ID_CLIENT2);
            default -> throw new IllegalArgumentException(
                    "Unknown lab command '" + command + "' (use USER, SAE, CL 1, or CL 2)");
        };
    }

    static String normalizeClient(String client) {
        Objects.requireNonNull(client, "client");
        String c = client.strip().toLowerCase().replace('_', '-').replace(' ', '-');
        return switch (c) {
            case "client-1", "client1", "cl-1", "cl1", "sae-1", "sae1", "1" -> ID_CLIENT1;
            case "client-2", "client2", "cl-2", "cl2", "sae-2", "sae2", "2" -> ID_CLIENT2;
            default -> throw new IllegalArgumentException(
                    "Unknown lab client '" + client + "' (use CL 1 or CL 2)");
        };
    }

    private static String token(String raw) {
        return raw.strip().toUpperCase().replace('-', ' ').replace('_', ' ');
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Node(String host, int nativePort, int terminalPort, String serialPort) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record State(String mode, String client, Map<String, Node> nodes) {
        public boolean holdsUser() {
            return MODE_USER.equals(mode);
        }

        public boolean holdsTerminal() {
            return MODE_SAE.equals(mode);
        }

        public String clientId() {
            return client == null || client.isBlank() ? ID_CLIENT1 : client;
        }

        public String targetId() {
            return clientId();
        }

        /** CL 1 ↔ SAE 1, CL 2 ↔ SAE 2. */
        public String saeId() {
            return ID_CLIENT2.equals(clientId()) ? "SAE 2" : "SAE 1";
        }

        public String clientLabel() {
            return ID_CLIENT2.equals(clientId()) ? "CL 2" : "CL 1";
        }

        /** Serial path of the selected client. */
        public String serialPort() {
            return node().serialPort();
        }

        public Node node() {
            Node n = nodes == null ? null : nodes.get(clientId());
            if (n == null) {
                throw new IllegalStateException("Lab switch has no node mapping for " + clientId());
            }
            return n;
        }

        public State withOwner(String owner) {
            return new State(owner, clientId(), nodes);
        }

        public State withClient(String nextClient) {
            return new State(mode, nextClient, nodes);
        }
    }
}
