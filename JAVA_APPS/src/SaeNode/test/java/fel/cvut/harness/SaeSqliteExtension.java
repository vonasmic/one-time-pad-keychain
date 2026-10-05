package fel.cvut.harness;

import com.zaxxer.hikari.HikariDataSource;
import fel.cvut.db.DB;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Creates two temporary SQLite databases (origin + peer SAE), migrates production Flyway
 * scripts onto both, and clears tables before every test.
 */
public final class SaeSqliteExtension implements BeforeAllCallback, BeforeEachCallback {

    private static final AtomicBoolean STARTED = new AtomicBoolean();
    private static Path originFile;
    private static Path peerFile;
    private static HikariDataSource originDataSource;
    private static HikariDataSource peerDataSource;
    private static volatile Throwable startupFailure;

    public DataSource origin() {
        requireStarted();
        return originDataSource;
    }

    public DataSource peer() {
        requireStarted();
        return peerDataSource;
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        startOnce();
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        startOnce();
        clear(originDataSource);
        clear(peerDataSource);
    }

    private static void startOnce() {
        if (STARTED.get()) {
            if (originDataSource == null) {
                throw new IllegalStateException("SQLite test harness failed to start", startupFailure);
            }
            return;
        }
        synchronized (STARTED) {
            if (STARTED.get()) {
                if (originDataSource == null) {
                    throw new IllegalStateException("SQLite test harness failed to start", startupFailure);
                }
                return;
            }
            try {
                Path dir = Files.createTempDirectory("sae-sqlite-");
                originFile = dir.resolve("origin.db");
                peerFile = dir.resolve("peer.db");
                Files.createFile(originFile);
                Files.createFile(peerFile);
                originDataSource = DB.openPool("jdbc:sqlite:" + originFile, "sae-test-origin");
                peerDataSource = DB.openPool("jdbc:sqlite:" + peerFile, "sae-test-peer");
                migrate(originDataSource);
                migrate(peerDataSource);
            } catch (Exception ex) {
                startupFailure = ex;
                STARTED.set(true);
                throw new IllegalStateException("Failed to start SQLite test harness", ex);
            }
            STARTED.set(true);
        }
    }

    private static void migrate(DataSource dataSource) {
        Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .load()
                .migrate();
    }

    private static void clear(DataSource dataSource) throws Exception {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute("DELETE FROM shared_key_material");
            statement.execute("DELETE FROM client_record_state");
            statement.execute("DELETE FROM application_log");
        }
    }

    private static void requireStarted() {
        startOnce();
    }
}
