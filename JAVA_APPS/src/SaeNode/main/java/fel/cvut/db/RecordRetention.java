package fel.cvut.db;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Timed thread that deletes {@code client_record_state} rows older than
 * {@code RECORD_RETENTION_DAYS} (default 14). Matching {@code shared_key_material}
 * rows are removed by {@code ON DELETE CASCADE}.
 *
 * <p>Also provides the shared expiry cutoff used to refuse serving stale rows
 * (defense against database replay).
 */
public final class RecordRetention implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(RecordRetention.class.getName());

    public static final int DEFAULT_RETENTION_DAYS = 14;

    private final DataSource dataSource;
    private final Duration retention;
    private final Object lock = new Object();
    private ScheduledExecutorService scheduler;

    public RecordRetention(DataSource dataSource, Duration retention) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource must not be null");
        this.retention = Objects.requireNonNull(retention, "retention must not be null");
        if (retention.isZero() || retention.isNegative()) {
            throw new IllegalArgumentException("retention must be positive");
        }
    }

    public static RecordRetention fromEnvironment(DataSource dataSource) {
        return new RecordRetention(dataSource, retentionFromEnvironment());
    }

    public static Duration retentionFromEnvironment() {
        return parseRetentionDays(System.getenv("RECORD_RETENTION_DAYS"));
    }

    public Duration retention() {
        return retention;
    }

    public Instant cutoff() {
        return Instant.now().minus(retention);
    }

    public boolean isExpired(Instant dateOfCreation) {
        Objects.requireNonNull(dateOfCreation, "dateOfCreation must not be null");
        return dateOfCreation.isBefore(cutoff());
    }

    /**
     * Purges immediately, then every 24 hours. Safe to call more than once.
     */
    public void start() {
        synchronized (lock) {
            if (scheduler != null) {
                return;
            }
            ScheduledExecutorService scheduled = Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread thread = new Thread(runnable, "record-retention");
                thread.setDaemon(true);
                return thread;
            });
            scheduled.scheduleAtFixedRate(this::runOnce, 0, 1, TimeUnit.DAYS);
            scheduler = scheduled;
            LOG.info("Record retention started — every 24h, RECORD_RETENTION_DAYS="
                    + retention.toDays());
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (scheduler != null) {
                scheduler.shutdownNow();
                scheduler = null;
            }
        }
    }

    static Duration parseRetentionDays(String value) {
        if (value == null || value.isBlank()) {
            return Duration.ofDays(DEFAULT_RETENTION_DAYS);
        }
        String trimmed = value.trim();
        final int days;
        try {
            days = Integer.parseInt(trimmed);
        } catch (NumberFormatException ex) {
            throw new IllegalStateException(
                    "RECORD_RETENTION_DAYS must be a positive integer, got: " + trimmed);
        }
        if (days < 1) {
            throw new IllegalStateException(
                    "RECORD_RETENTION_DAYS must be a positive integer, got: " + days);
        }
        return Duration.ofDays(days);
    }

    static int purgeExpired(DataSource dataSource, Duration retention) throws SQLException {
        Instant cutoff = Instant.now().minus(retention);
        try (Connection connection = dataSource.getConnection()) {
            return new ClientRecordStateRepository().deleteOlderThan(connection, cutoff);
        }
    }

    private void runOnce() {
        try {
            int deleted = purgeExpired(dataSource, retention);
            LOG.info("Record retention deleted=" + deleted
                    + " retentionDays=" + retention.toDays());
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Record retention purge failed: " + ex.getMessage(), ex);
        }
    }
}
