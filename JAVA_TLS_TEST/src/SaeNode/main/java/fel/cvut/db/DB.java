package fel.cvut.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * Factory for the node PostgreSQL pool.
 */
public final class DB {

    private DB() {}

    /**
     * Creates a HikariCP {@link HikariDataSource} from {@link DatabaseConfig} env vars.
     * Caller owns the pool and must {@link HikariDataSource#close()} it on shutdown.
     */
    public static HikariDataSource createDataSource() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(DatabaseConfig.getDbUrl());
        config.setUsername(DatabaseConfig.getDbUsername());
        config.setPassword(DatabaseConfig.getDbPassword());
        config.setPoolName("node-db-pool");
        return new HikariDataSource(config);
    }
}
