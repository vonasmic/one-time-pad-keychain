package fel.cvut.db;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

/**
 * Writes {@link LogRecord}s into {@code application_log} on a dedicated SQLite connection
 * so logging never borrows a connection from the node pool.
 */
final class SqliteLogHandler extends Handler {

    private static final String INSERT = """
            INSERT INTO application_log (logged_at, level, logger, thread, message, thrown)
            VALUES (?, ?, ?, ?, ?, ?)
            """;

    private final Object lock = new Object();
    private final AtomicBoolean failureReported = new AtomicBoolean();
    private final Connection connection;
    private boolean closed;

    SqliteLogHandler(String jdbcUrl) throws SQLException {
        Connection opened = DriverManager.getConnection(jdbcUrl);
        try (Statement statement = opened.createStatement()) {
            statement.execute("PRAGMA journal_mode = WAL");
            statement.execute("PRAGMA busy_timeout = 30000");
            try (ResultSet tables = statement.executeQuery(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'application_log'")) {
                if (!tables.next()) {
                    throw new SQLException(
                            "application_log is missing in " + jdbcUrl + "; run Flyway migrate");
                }
            }
        } catch (SQLException ex) {
            opened.close();
            throw ex;
        }
        connection = opened;
        setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                String message = formatMessage(record);
                return message == null ? "" : message;
            }
        });
    }

    @Override
    public void publish(LogRecord record) {
        if (!isLoggable(record)) {
            return;
        }
        String thrown = stackTrace(record);
        String message = getFormatter().format(record);
        String logger = record.getLoggerName() == null ? "" : record.getLoggerName();
        synchronized (lock) {
            if (closed) {
                return;
            }
            try (PreparedStatement statement = connection.prepareStatement(INSERT)) {
                statement.setString(1, Instant.ofEpochMilli(record.getMillis()).toString());
                statement.setString(2, record.getLevel().getName());
                statement.setString(3, logger);
                statement.setString(4, Thread.currentThread().getName());
                statement.setString(5, message);
                statement.setString(6, thrown);
                statement.executeUpdate();
            } catch (SQLException ex) {
                reportFailure(ex);
            } catch (RuntimeException ex) {
                reportFailure(new SQLException("SQLite log write failed", ex));
            }
        }
    }

    @Override
    public void flush() {
        synchronized (lock) {
            if (closed) {
                return;
            }
            try {
                if (!connection.getAutoCommit()) {
                    connection.commit();
                }
            } catch (SQLException ex) {
                reportFailure(ex);
            }
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (closed) {
                return;
            }
            closed = true;
            try {
                connection.close();
            } catch (SQLException ex) {
                System.err.println("SQLite log connection close failed: " + ex.getMessage());
            }
        }
    }

    private static String stackTrace(LogRecord record) {
        Throwable thrown = record.getThrown();
        if (thrown == null) {
            return null;
        }
        StringWriter writer = new StringWriter();
        thrown.printStackTrace(new PrintWriter(writer));
        return writer.toString();
    }

    private void reportFailure(SQLException ex) {
        if (failureReported.compareAndSet(false, true)) {
            System.err.println("SQLite log write failed: " + ex.getMessage());
        }
    }
}
