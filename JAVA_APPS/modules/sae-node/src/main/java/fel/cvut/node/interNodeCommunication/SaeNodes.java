package fel.cvut.node.interNodeCommunication;

import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.node.Address;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * SAE directory: the public, network-wide facts about every SAE, read from the file named by
 * {@value #ENV_FILE}. Every site holds an identical copy.
 *
 * <p>File format: a JSON array with one object per SAE, every field required:
 * {@code {"saeId": "sae-2", "name": "Bob", "location": "Berlin", "hostname": "127.0.0.1",
 * "port": 2020, "spkiSha384": "<96 hex chars>"}}. {@code name} selects the node identity
 * ({@code certs/{name}.pem} and the HSM key {@code {HSM_MLDSA_GROUP}/{name}}), {@code hostname}
 * and {@code port} are the advertised RMI registry address, and {@code spkiSha384} is the
 * lowercase hex SHA-384 of the SAE's leaf SubjectPublicKeyInfo ({@link KnownPeers#spkiSha384}).
 *
 * <p>The pins make the file a trust anchor: {@link #fromEnvironment} refuses a file that is not a
 * regular file or that is group- or other-writable.
 */
public final class SaeNodes {

    /** Env: path of the SAE directory; required to start a node. */
    public static final String ENV_FILE = "SAE_NODES_FILE";

    private static final int PIN_HEX_LENGTH = 96;
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]*");

    /** One SAE: id, node identity name, operator label, RMI registry address and leaf SPKI pin. */
    public record Entry(String saeId, String name, String location, Address address, String spkiSha384) {
        public Entry {
            saeId = requireText(saeId, "saeId");
            name = requireText(name, "name");
            if (!NAME.matcher(name).matches()) {
                throw new IllegalArgumentException("name must match " + NAME.pattern());
            }
            location = requireText(location, "location");
            Objects.requireNonNull(address, "address must not be null");
            String hostname = requireText(address.hostname, "hostname");
            if (address.port == null || address.port <= 0 || address.port > 65535) {
                throw new IllegalArgumentException("port must be 1-65535");
            }
            address = new Address(hostname, address.port);
            spkiSha384 = requirePin(spkiSha384);
        }
    }

    private final List<Entry> entries;
    private final Map<String, Entry> bySaeId;

    private SaeNodes(List<Entry> entries) {
        Map<String, Entry> map = new LinkedHashMap<>();
        Map<String, String> byName = new HashMap<>();
        Map<String, String> byPin = new HashMap<>();
        Map<String, String> byEndpoint = new HashMap<>();
        for (Entry e : entries) {
            Objects.requireNonNull(e, "entry must not be null");
            if (map.put(e.saeId(), e) != null) {
                throw new IllegalArgumentException("Duplicate saeId: " + e.saeId());
            }
            requireUnique(byName, e.name().toLowerCase(Locale.ROOT), e.saeId(), "name");
            requireUnique(byPin, e.spkiSha384(), e.saeId(), "spkiSha384");
            requireUnique(byEndpoint, e.address().hostname.toLowerCase(Locale.ROOT) + ":" + e.address().port,
                    e.saeId(), "hostname and port");
        }
        this.entries = List.copyOf(entries);
        this.bySaeId = Map.copyOf(map);
    }

    public static SaeNodes of(List<Entry> entries) {
        return new SaeNodes(Objects.requireNonNull(entries, "entries must not be null"));
    }

    /** Parses and validates {@code file}; malformed entries fail with {@link IllegalArgumentException}. */
    public static SaeNodes load(Path file) throws IOException {
        Objects.requireNonNull(file, "file must not be null");
        Row[] rows = new ObjectMapper().readValue(Files.readAllBytes(file), Row[].class);
        if (rows == null) {
            throw new IllegalArgumentException(file + " is not a JSON array of SAE entries");
        }
        List<Entry> entries = new ArrayList<>(rows.length);
        for (int i = 0; i < rows.length; i++) {
            Row row = rows[i];
            try {
                if (row == null) {
                    throw new IllegalArgumentException("entry is null");
                }
                if (row.port == null) {
                    throw new IllegalArgumentException("port must be 1-65535");
                }
                entries.add(new Entry(row.saeId, row.name, row.location,
                        new Address(Objects.toString(row.hostname, ""), row.port), row.spkiSha384));
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Invalid entry " + i + " in " + file + ": " + ex.getMessage(), ex);
            }
        }
        try {
            return new SaeNodes(entries);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(ex.getMessage() + " in " + file, ex);
        }
    }

    /**
     * Resolves symlinks, then requires a regular file that is neither group- nor other-writable
     * (where the file system has POSIX permissions) before {@link #load loading} it.
     */
    public static SaeNodes loadTrusted(Path file) throws IOException {
        Objects.requireNonNull(file, "file must not be null");
        Path real = file.toRealPath();
        if (!Files.isRegularFile(real)) {
            throw new IllegalArgumentException(real + " is not a regular file");
        }
        PosixFileAttributeView posix = Files.getFileAttributeView(real, PosixFileAttributeView.class);
        if (posix != null) {
            Set<PosixFilePermission> perms = posix.readAttributes().permissions();
            if (perms.contains(PosixFilePermission.GROUP_WRITE) || perms.contains(PosixFilePermission.OTHERS_WRITE)) {
                throw new IllegalArgumentException(real + " is group- or other-writable; it pins the RMI peers"
                        + " (use chmod 644 or stricter)");
            }
        }
        return load(real);
    }

    /** {@link #loadTrusted} on the file named by {@value #ENV_FILE}; fails with {@link IllegalStateException}. */
    public static SaeNodes fromEnvironment() {
        String file = System.getenv(ENV_FILE);
        if (file == null || file.isBlank()) {
            throw new IllegalStateException(ENV_FILE + " is not set: it must name the SAE directory (JSON "
                    + "[{\"saeId\",\"name\",\"location\",\"hostname\",\"port\",\"spkiSha384\"}])");
        }
        try {
            return loadTrusted(Path.of(file.trim()));
        } catch (IOException | RuntimeException ex) {
            throw new IllegalStateException("Cannot load " + ENV_FILE + " from " + file.trim() + ": " + ex.getMessage(), ex);
        }
    }

    public List<Entry> entries() {
        return entries;
    }

    public Optional<Entry> find(String saeId) {
        return saeId == null ? Optional.empty() : Optional.ofNullable(bySaeId.get(saeId.trim()));
    }

    /** The entry of the local SAE; fails with {@link IllegalStateException} when {@code saeId} has none. */
    public Entry self(String saeId) {
        return find(saeId).orElseThrow(() -> new IllegalStateException(
                "SAE_ID " + saeId + " has no entry in the SAE directory (" + ENV_FILE + ")"));
    }

    /**
     * Requires the own entry's {@code spkiSha384} to equal the SPKI SHA-384 of the node's own leaf,
     * so a swapped certificate or directory stops the node.
     */
    public static void requireOwnPin(Entry self, Certificate ownLeaf, String leafSource) {
        Objects.requireNonNull(self, "self must not be null");
        String actual = KnownPeers.spkiSha384(ownLeaf);
        if (!actual.equals(self.spkiSha384())) {
            throw new IllegalStateException("spkiSha384 of " + self.saeId() + " in the SAE directory does not match"
                    + " the own leaf " + leafSource + " (" + actual + ")");
        }
    }

    private static void requireUnique(Map<String, String> seen, String key, String saeId, String field) {
        String other = seen.put(key, saeId);
        if (other != null) {
            throw new IllegalArgumentException("SAE " + other + " and " + saeId + " share one " + field);
        }
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value.trim();
    }

    private static String requirePin(String value) {
        if (value == null || value.length() != PIN_HEX_LENGTH
                || !value.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            throw new IllegalArgumentException("spkiSha384 must be 96 lowercase hex characters");
        }
        return value;
    }

    private static final class Row {
        public String saeId;
        public String name;
        public String location;
        public String hostname;
        public Integer port;
        public String spkiSha384;
    }
}
