package fel.cvut.terminal;

import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Operator UI stays on the original stdout ({@link #terminalOut()}).
 * Everything else uses stderr, which is where {@link ConsoleHandler} already writes.
 *
 * <p>{@code APP_LOG=FULL} points {@link System#out} at stderr and turns loggers up,
 * so debug and Bouncy Castle show up there. {@code APP_LOG=TERMINAL} (default)
 * drops stdout and stderr after that. SQLite logging is unchanged.
 */
public final class AppLogging {

    public static final String ENV = "APP_LOG";

    public enum Mode {
        FULL,
        TERMINAL
    }

    private static final Object LOCK = new Object();
    private static PrintStream realOut;
    private static boolean julReady;
    private static boolean streamsBound;

    private AppLogging() {
    }

    public static Mode mode() {
        return parse(System.getenv(ENV));
    }

    /** {@code null} and blank are {@link Mode#TERMINAL}. */
    public static Mode parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Mode.TERMINAL;
        }
        String value = raw.trim();
        if (value.equalsIgnoreCase("FULL")) {
            return Mode.FULL;
        }
        if (value.equalsIgnoreCase("TERMINAL")) {
            return Mode.TERMINAL;
        }
        throw new IllegalStateException(ENV + " must be FULL or TERMINAL, got: " + value);
    }

    /** Operator UI. Not affected by the stderr redirect. */
    public static PrintStream terminalOut() {
        return realOut != null ? realOut : System.out;
    }

    /** Operator errors and warnings. Same stream as {@link #terminalOut()}. */
    public static PrintStream terminalErr() {
        return terminalOut();
    }

    /**
     * Call at the start of {@code Node} and {@code UserApplication} main,
     * before {@link fel.cvut.db.SqliteLogging#install}.
     */
    public static void bindTerminal() {
        synchronized (LOCK) {
            capture();
            if (streamsBound) {
                return;
            }
            streamsBound = true;
            installLocked();
            if (mode() == Mode.TERMINAL) {
                PrintStream sink = new PrintStream(OutputStream.nullOutputStream(), false, StandardCharsets.UTF_8);
                System.setOut(sink);
                System.setErr(sink);
                Thread.setDefaultUncaughtExceptionHandler((thread, error) -> error.printStackTrace(realOut));
                return;
            }
            System.setOut(System.err);
        }
    }

    /**
     * JUL levels and, in {@code FULL}, the builtin stderr {@link ConsoleHandler}.
     * Does not redirect streams, so tests can call this.
     */
    public static void install() {
        synchronized (LOCK) {
            capture();
            installLocked();
        }
    }

    private static void installLocked() {
        if (julReady) {
            return;
        }
        julReady = true;
        LogManager.getLogManager().reset();
        Logger root = Logger.getLogger("");
        if (mode() == Mode.FULL) {
            root.setLevel(Level.ALL);
            Logger.getLogger("fel.cvut").setLevel(Level.ALL);
            Logger.getLogger("org.bouncycastle").setLevel(Level.ALL);
            ConsoleHandler console = new ConsoleHandler();
            console.setLevel(Level.ALL);
            root.addHandler(console);
            return;
        }
        root.setLevel(Level.WARNING);
        Logger.getLogger("fel.cvut").setLevel(Level.INFO);
        Logger.getLogger("org.bouncycastle").setLevel(Level.WARNING);
    }

    /**
     * SQLite keeps application INFO and above, and WARNING and above from every other logger.
     * Same rule in {@code FULL} and {@code TERMINAL}.
     */
    public static boolean storedInSqlite(LogRecord record) {
        if (record == null || record.getLevel() == null) {
            return false;
        }
        String name = record.getLoggerName() == null ? "" : record.getLoggerName();
        int level = record.getLevel().intValue();
        if (name.equals("fel.cvut") || name.startsWith("fel.cvut.")) {
            return level >= Level.INFO.intValue();
        }
        return level >= Level.WARNING.intValue();
    }

    private static void capture() {
        if (realOut == null) {
            realOut = System.out;
        }
    }
}
