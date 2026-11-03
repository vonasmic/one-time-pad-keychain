package fel.cvut.db;

import fel.cvut.node.pairlock.PairKey;
import fel.cvut.node.pairlock.PairLockRegistry;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Timed thread that deletes {@code client_record_state} rows older than
 * {@code RECORD_RETENTION_DAYS} (default 14). Matching {@code shared_key_material}
 * rows are removed by {@code ON DELETE CASCADE}. Each expired row is deleted in its own
 * transaction through {@link PairLockRegistry#withFreePair}, so a pair an operation holds
 * the lock for is skipped (and purged on a later run).
 *
 * <p>Also provides the shared expiry cutoff used to refuse serving stale rows
 * (defense against database replay).
 */
public final class RecordRetention implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(RecordRetention.class.getName());

    public static final int DEFAULT_RETENTION_DAYS = 14;

    private final DataSource dataSource;
    private final PairLockRegistry registry;
    private final Duration retention;
    private final Object lock = new Object();
    private ScheduledExecutorService scheduler;

    public RecordRetention(DataSource dataSource, PairLockRegistry registry, Duration retention) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource must not be null");
        this.registry = Objects.requireNonNull(registry, "registry must not be null");
        this.retention = Objects.requireNonNull(retention, "retention must not be null");
        if (retention.isZero() || retention.isNegative()) {
            throw new IllegalArgumentException("retention must be positive");
        }
    }

    public static RecordRetention fromEnvironment(DataSource dataSource, PairLockRegistry registry) {
        return new RecordRetention(dataSource, registry, retentionFromEnvironment());
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

    public static Duration parseRetentionDays(String value) {
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

    public static int purgeExpired(DataSource dataSource, PairLockRegistry registry, Duration retention)
            throws SQLException {
        Instant cutoff = Instant.now().minus(retention);
        ClientRecordStateRepository repository = new ClientRecordStateRepository();
        List<String[]> expired;
        try (Connection connection = dataSource.getConnection()) {
            expired = repository.findOlderThan(connection, cutoff);
        }
        int deleted = 0;
        for (String[] pair : expired) {
            boolean removed = registry.withFreePair(PairKey.of(pair[0], pair[1]),
                    connection -> repository.deleteIfOlderThan(connection, pair[0], pair[1], cutoff))
                    .orElse(false);
            if (removed) {
                deleted++;
            }
        }
        return deleted;
    }

    private void runOnce() {
        try {
            int deleted = purgeExpired(dataSource, registry, retention);
            LOG.info("Record retention deleted=" + deleted
                    + " retentionDays=" + retention.toDays());
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Record retention purge failed: " + ex.getMessage(), ex);
        }
    }
}
