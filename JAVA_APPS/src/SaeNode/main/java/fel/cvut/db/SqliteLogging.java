package fel.cvut.db;

import java.sql.SQLException;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * Routes java.util.logging into the node SQLite file and the console.
 *
 * <p>{@code fel.cvut} is kept at {@link Level#INFO} so application messages are stored.
 * The root logger, including Bouncy Castle, stays at {@link Level#WARNING}.
 */
public final class SqliteLogging {

    static final String APPLICATION_LOGGER = "fel.cvut";
    private static final String BOUNCY_CASTLE_LOGGER = "org.bouncycastle";

    private static final Object LOCK = new Object();
    private static SqliteLogHandler sqliteHandler;
    private static boolean hookRegistered;

    private SqliteLogging() {}

    /**
     * Installs the console and SQLite handlers. Safe to call once per JVM; later calls do nothing.
     * The SQLite file is created with mode {@code 0600} when it does not exist yet.
     */
    public static void install(String jdbcUrl) {
        boolean registerHook = false;
        synchronized (LOCK) {
            if (sqliteHandler != null) {
                return;
            }
            DB.prepareSqliteFile(jdbcUrl);
            if (System.getProperty("java.util.logging.SimpleFormatter.format") == null) {
                System.setProperty(
                        "java.util.logging.SimpleFormatter.format",
                        "%1$tF %1$tT %4$-7s %3$s %5$s%6$s%n"
                );
            }
            LogManager.getLogManager().reset();

            Logger root = Logger.getLogger("");
            root.setLevel(Level.WARNING);

            ConsoleHandler console = new ConsoleHandler();
            console.setLevel(Level.ALL);
            root.addHandler(console);

            Logger.getLogger(APPLICATION_LOGGER).setLevel(Level.INFO);
            Logger.getLogger(BOUNCY_CASTLE_LOGGER).setLevel(Level.WARNING);

            try {
                SqliteLogHandler handler = new SqliteLogHandler(jdbcUrl);
                handler.setLevel(Level.ALL);
                root.addHandler(handler);
                sqliteHandler = handler;
                if (!hookRegistered) {
                    hookRegistered = true;
                    registerHook = true;
                }
            } catch (SQLException ex) {
                System.err.println("SQLite log handler disabled: " + ex.getMessage());
            }
        }
        if (registerHook) {
            Runtime.getRuntime().addShutdownHook(new Thread(SqliteLogging::close, "sqlite-log-close"));
        }
    }

    public static void close() {
        SqliteLogHandler handler;
        synchronized (LOCK) {
            handler = sqliteHandler;
            sqliteHandler = null;
        }
        if (handler != null) {
            handler.close();
        }
    }
}
