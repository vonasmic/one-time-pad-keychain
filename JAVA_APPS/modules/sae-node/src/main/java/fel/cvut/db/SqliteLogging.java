package fel.cvut.db;

import fel.cvut.terminal.AppLogging;

import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Routes java.util.logging into the node SQLite file.
 *
 * <p>Console printing is {@link AppLogging}: {@code APP_LOG=FULL} leaves logs on stderr,
 * {@code APP_LOG=TERMINAL} drops them. SQLite still stores {@code fel.cvut} at INFO
 * and above, and WARNING and above from every other logger, in both modes.
 */
public final class SqliteLogging {

    private static final Object LOCK = new Object();
    private static SqliteLogHandler sqliteHandler;
    private static boolean hookRegistered;

    private SqliteLogging() {}

    /**
     * Installs the SQLite handler. Safe to call once per JVM; later calls do nothing.
     * The SQLite file is created with mode {@code 0600} when it does not exist yet.
     * Also installs {@link AppLogging} console policy ({@code APP_LOG}).
     */
    public static void install(String jdbcUrl) {
        AppLogging.install();
        boolean registerHook = false;
        synchronized (LOCK) {
            if (sqliteHandler != null) {
                return;
            }
            DB.prepareSqliteFile(jdbcUrl);
            try {
                SqliteLogHandler handler = new SqliteLogHandler(jdbcUrl);
                handler.setLevel(Level.ALL);
                handler.setFilter(AppLogging::storedInSqlite);
                Logger.getLogger("").addHandler(handler);
                sqliteHandler = handler;
                if (!hookRegistered) {
                    hookRegistered = true;
                    registerHook = true;
                }
            } catch (SQLException ex) {
                AppLogging.terminalErr().println("SQLite log handler disabled: " + ex.getMessage());
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
