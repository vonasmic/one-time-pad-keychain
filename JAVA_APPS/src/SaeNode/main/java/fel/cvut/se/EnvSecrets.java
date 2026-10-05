package fel.cvut.se;

import java.io.Console;
import java.io.IOException;
import java.util.Map;

/**
 * Secrets an attacker must not read from defaults: take the env var when set,
 * otherwise an optional env-file value, otherwise prompt on stdin (masked when a
 * console is attached).
 */
public final class EnvSecrets {

    private EnvSecrets() {
    }

    /**
     * First non-blank value among {@code names} in the process environment,
     * else prompt using {@code names[0]}.
     *
     * @throws IllegalStateException if unset and stdin has no line
     */
    public static String envOrScan(String... names) {
        return envOrScan(null, names);
    }

    /**
     * Like {@link #envOrScan(String...)}, but after env also checks {@code fileValues}
     * (e.g. keys from {@code env/certgen.env} that were not exported into the process).
     */
    public static String envOrScan(Map<String, String> fileValues, String... names) {
        if (names == null || names.length == 0) {
            throw new IllegalArgumentException("at least one env name required");
        }
        for (String name : names) {
            String v = System.getenv(name);
            if (v != null && !v.isBlank()) {
                return v.trim();
            }
        }
        if (fileValues != null) {
            for (String name : names) {
                String v = fileValues.get(name);
                if (v != null && !v.isBlank()) {
                    return v.trim();
                }
            }
        }
        return scan(names[0]);
    }

    private static String scan(String name) {
        Console console = System.console();
        if (console != null) {
            char[] pw = console.readPassword("%s: ", name);
            if (pw == null) {
                throw new IllegalStateException(name + " required");
            }
            return new String(pw);
        }
        System.out.print(name + ": ");
        System.out.flush();
        try {
            StringBuilder sb = new StringBuilder();
            while (true) {
                int ch = System.in.read();
                if (ch < 0) {
                    throw new IllegalStateException(name + " required");
                }
                if (ch == '\n') {
                    break;
                }
                if (ch != '\r') {
                    sb.append((char) ch);
                }
            }
            return sb.toString();
        } catch (IOException e) {
            throw new IllegalStateException(name + " required", e);
        }
    }
}
