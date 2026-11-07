package fel.cvut.terminal;

import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Operator UI stays on the original stdout ({@link #terminalOut()}).
 * Everything else uses stderr, which is where {@link ConsoleHandler} already writes.
 *
 * <p>{@code APP_LOG=FULL} points {@link System#out} at stderr and turns loggers up,
 * so debug and Bouncy Castle show up there. {@code APP_LOG=TERMINAL} (default;
 * also used when the variable is unset) drops stdout and stderr after that.
 * The terminal then shows operator text and {@code SEVERE} records only
 * ({@link #terminalLine}: level, message, exception message, no stack trace).
 * INFO and WARNING stay in SQLite and off the terminal.
 */
public final class AppLogging {

    public static final String ENV = "APP_LOG";

    public enum Mode {
        FULL,
        TERMINAL
    }

    private static final Object LOCK = new Object();
    private static PrintStream realOut;
    private static PrintStream realErr;
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

    /** Operator errors. Same stream as {@link #terminalOut()}. */
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
        root.addHandler(new TerminalAlertHandler(realErr));
    }

    /**
     * One terminal line for a {@code SEVERE} record in {@code TERMINAL} mode:
     * level, message, and the exception message when the message does not already contain it.
     * No stack trace ({@code FULL} prints those).
     */
    public static String terminalLine(LogRecord record) {
        String message = new Formatter() {
            @Override
            public String format(LogRecord r) {
                return formatMessage(r);
            }
        }.format(record);
        StringBuilder line = new StringBuilder(record.getLevel().getName()).append(": ")
                .append(message == null ? "" : message);
        Throwable thrown = record.getThrown();
        if (thrown != null) {
            String detail = thrown.getMessage();
            if (detail == null || detail.isBlank()) {
                line.append(" (").append(thrown.getClass().getSimpleName()).append(')');
            } else if (message == null || !message.contains(detail)) {
                line.append(": ").append(thrown.getClass().getSimpleName()).append(": ").append(detail);
            }
        }
        return line.toString();
    }

    /** {@code SEVERE} reaches the terminal. INFO and WARNING stay in SQLite only. */
    public static boolean shownOnTerminal(LogRecord record) {
        return record != null && record.getLevel() != null
                && record.getLevel().intValue() >= Level.SEVERE.intValue();
    }

    /** {@code SEVERE} to the original stderr. INFO and WARNING stay off the terminal. */
    private static final class TerminalAlertHandler extends Handler {
        private final PrintStream out;

        TerminalAlertHandler(PrintStream out) {
            this.out = out;
            setLevel(Level.SEVERE);
        }

        @Override
        public synchronized void publish(LogRecord record) {
            if (record == null || !isLoggable(record) || !shownOnTerminal(record)) {
                return;
            }
            out.println(terminalLine(record));
            out.flush();
        }

        @Override
        public void flush() {
            out.flush();
        }

        @Override
        public void close() {
            out.flush();
        }
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
        if (realErr == null) {
            realErr = System.err;
        }
    }
}
