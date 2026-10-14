package fel.cvut.se;

import java.io.Console;
import java.util.Map;

/**
 * Secrets an attacker must not read from defaults: take the env var when set,
 * otherwise an optional env-file value, otherwise a masked prompt on the interactive
 * console. Without a console the call fails; stdin is never read.
 */
public final class EnvSecrets {

    private EnvSecrets() {
    }

    /**
     * First non-blank value among {@code names} in the process environment,
     * else prompt using {@code names[0]}.
     *
     * @throws IllegalStateException if unset and no console is attached (or the prompt is cancelled)
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
        Console console = interactiveConsole();
        if (console == null) {
            // F-13: never read a secret from a non-console stdin (it would echo and can be piped/logged).
            throw new IllegalStateException(name + " is not set and no interactive console is attached;"
                    + " export " + name + " (or put it in the env file) or run from a terminal");
        }
        char[] pw = console.readPassword("%s: ", name);
        if (pw == null) {
            throw new IllegalStateException(name + " required");
        }
        return new String(pw);
    }

    /**
     * The console only when it is a real terminal. JDK 22+ returns a {@link Console} even for
     * redirected streams; {@code Console.isTerminal()} (looked up reflectively, absent on 21)
     * tells the two apart.
     */
    static Console interactiveConsole() {
        Console console = System.console();
        if (console == null) {
            return null;
        }
        try {
            Object terminal = Console.class.getMethod("isTerminal").invoke(console);
            return Boolean.TRUE.equals(terminal) ? console : null;
        } catch (NoSuchMethodException e) {
            return console;
        } catch (ReflectiveOperationException e) {
            return null;
        }
    }
}
