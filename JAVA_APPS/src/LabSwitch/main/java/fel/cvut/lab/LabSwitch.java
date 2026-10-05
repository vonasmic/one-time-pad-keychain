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
 * Lab-only shared switch file: USB owner is {@code USER} or {@code SAE}.
 *
 * <p>Both keychains run in parallel. {@code scripts/lab-run.py} pins
 * {@code userapp-1}/{@code terminal-1} to client-1 and {@code userapp-2}/{@code terminal-2}
 * to client-2. Owner toggles which app type may open USB on both PTYs at once.
 * Production Java does not import this package.
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

    /** Apply a CLI token: {@code USER} or {@code SAE}. */
    public State apply(String command) {
        String owner = parseOwner(command);
        return update(s -> s.withOwner(owner));
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
        Map<String, Node> incoming = raw == null || raw.nodes() == null ? Map.of() : raw.nodes();
        Map<String, Node> nodes = new LinkedHashMap<>();
        nodes.put(ID_CLIENT1, completeNode(
                incoming.get(ID_CLIENT1),
                "127.0.0.1", 11111, 11112, DEFAULT_SERIAL_CLIENT1));
        nodes.put(ID_CLIENT2, completeNode(
                incoming.get(ID_CLIENT2),
                "127.0.0.1", 5020, 11113, DEFAULT_SERIAL_CLIENT2));
        if (raw == null) {
            return new State(MODE_USER, nodes);
        }
        String token = raw.mode() == null ? "" : token(raw.mode());
        String mode = switch (token) {
            case "SAE", "TERM", "TERMINAL", "T" -> MODE_SAE;
            default -> MODE_USER;
        };
        return new State(mode, nodes);
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

    private static String parseOwner(String command) {
        Objects.requireNonNull(command, "command");
        return switch (token(command)) {
            case "USER", "U", "HOME" -> MODE_USER;
            case "SAE", "TERM", "TERMINAL", "T" -> MODE_SAE;
            default -> throw new IllegalArgumentException(
                    "Unknown lab command '" + command + "' (use USER or SAE)");
        };
    }

    private static String token(String raw) {
        return raw.strip().toUpperCase().replace('-', ' ').replace('_', ' ');
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Node(String host, int nativePort, int terminalPort, String serialPort) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record State(String mode, Map<String, Node> nodes) {
        public boolean holdsUser() {
            return MODE_USER.equals(mode);
        }

        public boolean holdsTerminal() {
            return MODE_SAE.equals(mode);
        }

        public Node node(String clientId) {
            Node n = nodes == null ? null : nodes.get(clientId);
            if (n == null) {
                throw new IllegalStateException("Lab switch has no node mapping for " + clientId);
            }
            return n;
        }

        public State withOwner(String owner) {
            return new State(owner, nodes);
        }
    }
}
