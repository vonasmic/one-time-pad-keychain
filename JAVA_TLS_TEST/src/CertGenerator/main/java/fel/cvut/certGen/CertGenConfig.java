package fel.cvut.certGen;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Names and lists for {@link CertGenerator}: {@code env/certgen.env} (or {@code CERTGEN_ENV}),
 * with already-exported environment variables taking precedence.
 */
final class CertGenConfig {

    static final String DEFAULT_ENV_FILE = "env/certgen.env";
    static final String DEFAULT_ROOT_CA = "root-ca";
    static final String DEFAULT_CLIENT_CA = "client_ca";

    private final String rootCaName;
    private final String clientCaName;
    private final List<String> nodes;
    private final List<String> clients;

    CertGenConfig(String rootCaName, String clientCaName, List<String> nodes, List<String> clients) {
        this.rootCaName = rootCaName;
        this.clientCaName = clientCaName;
        this.nodes = List.copyOf(nodes);
        this.clients = List.copyOf(clients);
    }

    static CertGenConfig load() throws IOException {
        Path envFile = envFilePath();
        Map<String, String> fromFile = Map.of();
        if (Files.isRegularFile(envFile)) {
            fromFile = parseEnvFile(envFile);
            System.out.println("[*] CertGenerator config: " + envFile.toAbsolutePath());
        } else {
            System.out.println("[*] No " + envFile + " — using process environment only.");
        }
        return from(fromFile);
    }

    static Path envFilePath() {
        String override = System.getenv("CERTGEN_ENV");
        if (override != null && !override.isBlank()) {
            return Path.of(override.trim());
        }
        return Path.of(DEFAULT_ENV_FILE);
    }

    static CertGenConfig from(Map<String, String> fileValues) {
        String rootCa = token(value(fileValues, "CERTGEN_ROOT_CA", DEFAULT_ROOT_CA), "CERTGEN_ROOT_CA");
        String clientCa = token(value(fileValues, "CERTGEN_CLIENT_CA", DEFAULT_CLIENT_CA), "CERTGEN_CLIENT_CA");
        List<String> nodes = names(value(fileValues, "CERTGEN_NODES", ""), "CERTGEN_NODES");
        List<String> clients = names(value(fileValues, "CERTGEN_CLIENTS", ""), "CERTGEN_CLIENTS");
        if (nodes.isEmpty()) {
            throw new IllegalStateException(
                    "CERTGEN_NODES is empty. Copy env/example/certgen.env.example to env/certgen.env "
                            + "(or export CERTGEN_NODES / set CERTGEN_ENV).");
        }
        if (rootCa.equals(clientCa)) {
            throw new IllegalStateException("CERTGEN_ROOT_CA and CERTGEN_CLIENT_CA must differ");
        }
        return new CertGenConfig(rootCa, clientCa, nodes, clients);
    }

    static Map<String, String> parseEnvFile(Path path) throws IOException {
        Map<String, String> out = new LinkedHashMap<>();
        for (String raw : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("export ")) {
                line = line.substring("export ".length()).trim();
            }
            int eq = line.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = line.substring(0, eq).trim();
            String val = unquote(line.substring(eq + 1).trim());
            if (!key.isEmpty()) {
                out.put(key, val);
            }
        }
        return out;
    }

    String rootCaName() {
        return rootCaName;
    }

    String clientCaName() {
        return clientCaName;
    }

    List<String> nodes() {
        return nodes;
    }

    List<String> clients() {
        return clients;
    }

    private static String value(Map<String, String> fileValues, String key, String defaultValue) {
        String env = System.getenv(key);
        if (env != null && !env.isBlank()) {
            return env.trim();
        }
        String fromFile = fileValues.get(key);
        if (fromFile != null && !fromFile.isBlank()) {
            return fromFile.trim();
        }
        return defaultValue;
    }

    static List<String> names(String csv, String what) {
        if (csv == null || csv.isBlank()) {
            return List.of();
        }
        Set<String> seen = new LinkedHashSet<>();
        List<String> out = new ArrayList<>();
        for (String part : csv.split(",")) {
            String name = token(part, what);
            if (!seen.add(name)) {
                throw new IllegalArgumentException("Duplicate name in " + what + ": " + name);
            }
            out.add(name);
        }
        return List.copyOf(out);
    }

    static String token(String raw, String what) {
        String t = raw == null ? "" : raw.trim();
        if (t.endsWith(".pem") || t.endsWith(".p12")) {
            t = t.substring(0, t.lastIndexOf('.')).trim();
        }
        if (t.isEmpty() || t.indexOf('/') >= 0 || t.indexOf('\\') >= 0 || t.contains("..") || t.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("Invalid " + what + " name: " + raw);
        }
        return t;
    }

    private static String unquote(String val) {
        if (val.length() >= 2) {
            char first = val.charAt(0);
            char last = val.charAt(val.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return val.substring(1, val.length() - 1);
            }
        }
        return val;
    }
}
