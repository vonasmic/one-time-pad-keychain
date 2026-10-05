package fel.cvut.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.sqlite.SQLiteConfig;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/**
 * Factory for the node SQLite pool.
 */
public final class DB {

    private static final String SQLITE_PREFIX = "jdbc:sqlite:";
    private static final int MAX_POOL_SIZE = 8;
    private static final int BUSY_TIMEOUT_MS = 30_000;

    private DB() {}

    /**
     * Creates a HikariCP {@link HikariDataSource} from {@link DatabaseConfig} env vars.
     * Ensures the SQLite file exists with mode {@code 0600} when the URL points at a file path.
     * Caller owns the pool and must {@link HikariDataSource#close()} it on shutdown.
     */
    public static HikariDataSource createDataSource() {
        String jdbcUrl = DatabaseConfig.getDbUrl();
        prepareSqliteFile(jdbcUrl);
        return openPool(jdbcUrl, "node-db-pool");
    }

    /**
     * Opens a SQLite pool with WAL, foreign keys, busy timeout, and IMMEDIATE transactions.
     */
    public static HikariDataSource openPool(String jdbcUrl, String poolName) {
        SQLiteConfig sqliteConfig = new SQLiteConfig();
        sqliteConfig.enforceForeignKeys(true);
        sqliteConfig.setJournalMode(SQLiteConfig.JournalMode.WAL);
        sqliteConfig.setBusyTimeout(BUSY_TIMEOUT_MS);
        // Stronger than deferred: write lock acquired when autoCommit is disabled.
        sqliteConfig.setTransactionMode(SQLiteConfig.TransactionMode.IMMEDIATE);

        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(jdbcUrl);
        config.setPoolName(poolName);
        config.setMaximumPoolSize(MAX_POOL_SIZE);
        config.setDataSourceProperties(sqliteConfig.toProperties());
        return new HikariDataSource(config);
    }

    static void prepareSqliteFile(String jdbcUrl) {
        Path dbPath = sqliteFilePath(jdbcUrl);
        if (dbPath == null) {
            return;
        }
        try {
            Path parent = dbPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            if (!Files.exists(dbPath)) {
                Files.createFile(dbPath);
            }
            restrictToOwnerReadWrite(dbPath);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to prepare SQLite database file: " + dbPath, ex);
        }
    }

    /**
     * @return absolute path for {@code jdbc:sqlite:/path} or {@code jdbc:sqlite:path}; null for
     *         memory / empty URLs
     */
    static Path sqliteFilePath(String jdbcUrl) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(SQLITE_PREFIX)) {
            throw new IllegalArgumentException("DB_URL must be a jdbc:sqlite: URL, got: " + jdbcUrl);
        }
        String pathPart = jdbcUrl.substring(SQLITE_PREFIX.length());
        if (pathPart.isBlank() || ":memory:".equals(pathPart) || pathPart.startsWith("file::memory:")) {
            return null;
        }
        if (pathPart.startsWith("file:")) {
            pathPart = pathPart.substring("file:".length());
            int query = pathPart.indexOf('?');
            if (query >= 0) {
                pathPart = pathPart.substring(0, query);
            }
        }
        if (pathPart.isBlank() || ":memory:".equals(pathPart)) {
            return null;
        }
        return Path.of(pathPart).toAbsolutePath().normalize();
    }

    private static void restrictToOwnerReadWrite(Path dbPath) throws IOException {
        Set<PosixFilePermission> ownerOnly = EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE
        );
        try {
            Files.setPosixFilePermissions(dbPath, ownerOnly);
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystems: best-effort skip.
        }
    }
}
