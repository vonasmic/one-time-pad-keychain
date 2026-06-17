package fel.cvut.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.Connection;
import java.sql.SQLException;

public final class DB {
    private static final HikariDataSource DATA_SOURCE = createDataSource();

    private DB() {}

    public static Connection connect() throws SQLException {
        return DATA_SOURCE.getConnection();
    }

    public static void close() {
        DATA_SOURCE.close();
    }

    private static HikariDataSource createDataSource() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(DatabaseConfig.getDbUrl());
        config.setUsername(DatabaseConfig.getDbUsername());
        config.setPassword(DatabaseConfig.getDbPassword());
        config.setPoolName("node-db-pool");
        return new HikariDataSource(config);
    }
}
