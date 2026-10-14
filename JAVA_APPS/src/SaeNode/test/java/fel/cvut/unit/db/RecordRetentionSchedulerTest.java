package fel.cvut.unit.db;

import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.db.RecordRetention;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Timeout(60)
@Tag("unit")
class RecordRetentionSchedulerTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();


    @Test
    void cutoffAndExpiryFollowRetention() {
        Duration retention = Duration.ofDays(3);
        RecordRetention rr = new RecordRetention(SQLITE.origin(), retention);
        assertSame(retention, rr.retention());
        Instant expected = Instant.now().minus(retention);
        assertTrue(Math.abs(Duration.between(expected, rr.cutoff()).toMillis()) < 5_000);
        assertTrue(rr.isExpired(Instant.now().minus(4, ChronoUnit.DAYS)));
        assertFalse(rr.isExpired(Instant.now().minus(2, ChronoUnit.DAYS)));
        assertThrows(NullPointerException.class, () -> rr.isExpired(null));
    }


    @Test
    void startPurgesImmediatelyAndIsIdempotent() throws Exception {
        try (Connection connection = SQLITE.origin().getConnection()) {
            new ClientRecordStateRepository().replace(connection, HASH_1, HASH_2,
                    new AtomicRecordStateMap.RecordMetadata(Instant.now().minus(30, ChronoUnit.DAYS),
                            AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                            ORIGIN_SAE, ORIGIN_SAE, SaeFixtures.padPlain()));
        }
        assertEquals(1, SaeFixtures.countRecords(SQLITE.origin()));
        RecordRetention rr = new RecordRetention(SQLITE.origin(), Duration.ofDays(14));
        try {
            rr.start();
            rr.start();
            long deadline = System.currentTimeMillis() + 10_000;
            while (SaeFixtures.countRecords(SQLITE.origin()) != 0 && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            assertEquals(0, SaeFixtures.countRecords(SQLITE.origin()));
        } finally {
            rr.close();
        }
        assertDoesNotThrow(rr::close);
    }

    @Test
    void scheduledPurgeFailureIsLoggedNotThrown() throws Exception {
        DataSource broken = mock(DataSource.class);
        when(broken.getConnection()).thenThrow(new SQLException("db down"));
        RecordRetention rr = new RecordRetention(broken, Duration.ofDays(1));
        try {
            assertDoesNotThrow(rr::start);
            verify(broken, timeout(10_000).atLeastOnce()).getConnection();
        } finally {
            rr.close();
        }
        assertThrows(SQLException.class, () -> RecordRetention.purgeExpired(broken, Duration.ofDays(1)));
    }

    @Test
    void restartAfterCloseSchedulesAgain() throws Exception {
        DataSource ds = mock(DataSource.class);
        when(ds.getConnection()).thenThrow(new SQLException("x"));
        RecordRetention rr = new RecordRetention(ds, Duration.ofDays(1));
        rr.start();
        verify(ds, timeout(10_000).times(1)).getConnection();
        rr.close();
        rr.start();
        verify(ds, timeout(10_000).times(2)).getConnection();
        rr.close();
        verify(ds, atLeastOnce()).getConnection();
    }
}