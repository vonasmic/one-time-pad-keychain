package fel.cvut.db;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SqliteLoggingTest {

    @Test
    void storesApplicationLogsAndWarningsFromOtherLoggers() throws Exception {
        Path directory = Files.createTempDirectory("sae-log-");
        Path database = directory.resolve("node.db");
        String jdbcUrl = "jdbc:sqlite:" + database;
        Flyway.configure()
                .dataSource(jdbcUrl, null, null)
                .locations("classpath:db/migration")
                .load()
                .migrate();

        SqliteLogging.install(jdbcUrl);

        Logger application = Logger.getLogger("fel.cvut.node.Node");
        Logger bouncyCastle = Logger.getLogger("org.bouncycastle.jsse.provider.ProvTlsServer");
        Logger hikari = Logger.getLogger("com.zaxxer.hikari.pool.HikariPool");

        application.fine("app-fine");
        application.info("app-info");
        application.log(Level.WARNING, "app-warn", new IllegalStateException("boom"));
        bouncyCastle.fine("bc-fine");
        bouncyCastle.info("bc-info");
        bouncyCastle.warning("bc-warn");
        hikari.info("hikari-info");
        hikari.warning("hikari-warn");

        Map<String, String> rows = readLogs(jdbcUrl);
        assertEquals("INFO", rows.get("app-info"));
        assertEquals("WARNING", rows.get("app-warn"));
        assertEquals("WARNING", rows.get("bc-warn"));
        assertEquals("WARNING", rows.get("hikari-warn"));
        assertFalse(rows.containsKey("app-fine"));
        assertFalse(rows.containsKey("bc-fine"));
        assertFalse(rows.containsKey("bc-info"));
        assertFalse(rows.containsKey("hikari-info"));

        try (Connection connection = DriverManager.getConnection(jdbcUrl);
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(
                     "SELECT thrown FROM application_log WHERE message = 'app-warn'")) {
            assertTrue(resultSet.next());
            String thrown = resultSet.getString(1);
            assertTrue(thrown.contains("IllegalStateException"));
            assertTrue(thrown.contains("boom"));
        }
    }

    private static Map<String, String> readLogs(String jdbcUrl) throws Exception {
        Map<String, String> rows = new LinkedHashMap<>();
        try (Connection connection = DriverManager.getConnection(jdbcUrl);
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(
                     "SELECT level, message FROM application_log ORDER BY id")) {
            while (resultSet.next()) {
                rows.put(resultSet.getString("message"), resultSet.getString("level"));
            }
        }
        return rows;
    }
}
