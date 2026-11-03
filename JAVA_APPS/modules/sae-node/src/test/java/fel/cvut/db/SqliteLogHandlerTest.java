package fel.cvut.db;

import fel.cvut.harness.SaeSqliteExtension;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Lives in {@code fel.cvut.db} because {@link SqliteLogHandler} is package-private. */
@Timeout(60)
@Tag("unit")
class SqliteLogHandlerTest {

    private static final String LOGGER = "fel.cvut.test.SqliteLogHandlerTest";

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    @Test
    void refusesDatabaseWithoutApplicationLogTable(@TempDir Path dir) throws Exception {
        Path db = dir.resolve("empty.db");
        Files.createFile(db);
        SQLException ex = assertThrows(SQLException.class, () -> new SqliteLogHandler("jdbc:sqlite:" + db));
        assertTrue(ex.getMessage().contains("application_log is missing"), ex.getMessage());
    }

    @Test
    void publishStoresFormattedMessageLevelLoggerThreadAndStackTrace() throws Exception {
        SqliteLogHandler handler = new SqliteLogHandler(SQLITE.originJdbcUrl());
        try {
            LogRecord plain = new LogRecord(Level.INFO, "retention deleted={0}");
            plain.setLoggerName(LOGGER);
            plain.setParameters(new Object[] {7});
            handler.publish(plain);

            LogRecord failure = new LogRecord(Level.SEVERE, "purge failed");
            failure.setLoggerName(LOGGER);
            failure.setThrown(new IllegalStateException("boom"));
            handler.publish(failure);
            handler.flush();
        } finally {
            handler.close();
        }

        List<String[]> rows = rows(LOGGER);
        assertEquals(2, rows.size());
        assertEquals("INFO", rows.get(0)[0]);
        assertEquals("retention deleted=7", rows.get(0)[1]);
        assertNull(rows.get(0)[2]);
        assertEquals(Thread.currentThread().getName(), rows.get(0)[3]);
        assertEquals("SEVERE", rows.get(1)[0]);
        assertTrue(rows.get(1)[2].contains("java.lang.IllegalStateException: boom"), rows.get(1)[2]);
    }

    @Test
    void respectsHandlerLevelAndStoresEmptyLoggerName() throws Exception {
        SqliteLogHandler handler = new SqliteLogHandler(SQLITE.originJdbcUrl());
        try {
            handler.setLevel(Level.WARNING);
            LogRecord info = new LogRecord(Level.INFO, "dropped");
            info.setLoggerName(LOGGER);
            handler.publish(info);
            LogRecord anonymous = new LogRecord(Level.WARNING, "kept");
            handler.publish(anonymous);
        } finally {
            handler.close();
        }
        assertTrue(rows(LOGGER).isEmpty());
        List<String[]> anon = rows("");
        assertEquals(1, anon.size());
        assertEquals("kept", anon.get(0)[1]);
    }

    @Test
    void publishAndFlushAfterCloseAreNoOps() throws Exception {
        SqliteLogHandler handler = new SqliteLogHandler(SQLITE.originJdbcUrl());
        handler.close();
        assertDoesNotThrow(handler::close);
        LogRecord late = new LogRecord(Level.SEVERE, "after close");
        late.setLoggerName(LOGGER);
        assertDoesNotThrow(() -> handler.publish(late));
        assertDoesNotThrow(handler::flush);
        assertTrue(rows(LOGGER).isEmpty());
    }


    private static List<String[]> rows(String logger) throws Exception {
        List<String[]> out = new ArrayList<>();
        try (Connection connection = SQLITE.origin().getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT level, message, thrown, thread FROM application_log WHERE logger = ? ORDER BY rowid")) {
            statement.setString(1, logger);
            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    out.add(new String[] {rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)});
                }
            }
        }
        return out;
    }
}