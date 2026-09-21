package fel.cvut.harness;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;

import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.Statement;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Starts PostgreSQL, migrates the production Flyway scripts onto two databases
 * (origin + peer SAE), and truncates both before every test.
 *
 * <p>Uses Testcontainers when Docker is available; otherwise falls back to
 * embedded PostgreSQL so {@code mvn test} stays automatic without a local
 * {@code createdb}.
 */
public final class SaePostgresExtension implements BeforeAllCallback, BeforeEachCallback {

    private static final AtomicBoolean STARTED = new AtomicBoolean();
    private static PostgreSQLContainer<?> container;
    private static EmbeddedPostgres embedded;
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
        truncate(originDataSource);
        truncate(peerDataSource);
    }

    private static void startOnce() {
        if (STARTED.get()) {
            if (originDataSource == null) {
                throw new IllegalStateException("PostgreSQL test harness failed to start", startupFailure);
            }
            return;
        }
        synchronized (STARTED) {
            if (STARTED.get()) {
                if (originDataSource == null) {
                    throw new IllegalStateException("PostgreSQL test harness failed to start", startupFailure);
                }
                return;
            }
            try {
                if (dockerAvailable()) {
                    startTestcontainers();
                } else {
                    startEmbedded();
                }
            } catch (Exception ex) {
                startupFailure = ex;
                STARTED.set(true);
                throw new IllegalStateException("Failed to start PostgreSQL test harness", ex);
            }
            STARTED.set(true);
        }
    }

    private static boolean dockerAvailable() {
        if (!java.nio.file.Files.exists(java.nio.file.Path.of("/var/run/docker.sock"))) {
            return false;
        }
        try {
            return CompletableFuture.supplyAsync(() -> DockerClientFactory.instance().isDockerAvailable())
                    .orTimeout(3, TimeUnit.SECONDS)
                    .join();
        } catch (Exception ignored) {
            return false;
        }
    }

    private static void startTestcontainers() {
        container = new PostgreSQLContainer<>("postgres:16-alpine");
        container.start();
        originDataSource = openPool(container.getJdbcUrl(), container.getUsername(), container.getPassword());
        migrate(originDataSource);
        createDatabase(originDataSource, "sae_peer");
        peerDataSource = openPool(
                jdbcUrlForDatabase(container.getJdbcUrl(), container.getDatabaseName(), "sae_peer"),
                container.getUsername(),
                container.getPassword()
        );
        migrate(peerDataSource);
    }

    private static void startEmbedded() throws IOException {
        embedded = EmbeddedPostgres.builder().start();
        String hostUrl = "jdbc:postgresql://localhost:" + embedded.getPort();
        originDataSource = openPool(hostUrl + "/postgres", "postgres", "");
        migrate(originDataSource);
        createDatabase(originDataSource, "sae_peer");
        peerDataSource = openPool(hostUrl + "/sae_peer", "postgres", "");
        migrate(peerDataSource);
    }

    private static HikariDataSource openPool(String jdbcUrl, String username, String password) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(jdbcUrl);
        config.setUsername(username);
        config.setPassword(password);
        config.setMaximumPoolSize(16);
        config.setPoolName("sae-test-" + Integer.toHexString(jdbcUrl.hashCode()));
        return new HikariDataSource(config);
    }

    private static void migrate(DataSource dataSource) {
        Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .load()
                .migrate();
    }

    private static String jdbcUrlForDatabase(String jdbcUrl, String currentDatabase, String databaseName) {
        String current = "/" + currentDatabase;
        int index = jdbcUrl.indexOf(current);
        if (index < 0) {
            throw new IllegalStateException("Unexpected JDBC URL: " + jdbcUrl);
        }
        return jdbcUrl.substring(0, index) + "/" + databaseName + jdbcUrl.substring(index + current.length());
    }

    private static void createDatabase(DataSource admin, String name) {
        try (Connection connection = admin.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE " + name);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to create database " + name, ex);
        }
    }

    private static void truncate(DataSource dataSource) throws Exception {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("TRUNCATE TABLE client_record_state CASCADE");
        }
    }

    private static void requireStarted() {
        startOnce();
    }
}
