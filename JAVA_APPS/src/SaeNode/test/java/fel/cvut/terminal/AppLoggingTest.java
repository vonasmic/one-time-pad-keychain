package fel.cvut.terminal;

import org.junit.jupiter.api.Test;

import java.util.logging.Level;
import java.util.logging.LogRecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppLoggingTest {

    @Test
    void onlyFullAndTerminal() {
        assertEquals(AppLogging.Mode.TERMINAL, AppLogging.parse(null));
        assertEquals(AppLogging.Mode.TERMINAL, AppLogging.parse("  "));
        assertEquals(AppLogging.Mode.TERMINAL, AppLogging.parse("terminal"));
        assertEquals(AppLogging.Mode.FULL, AppLogging.parse("FULL"));
        assertThrows(IllegalStateException.class, () -> AppLogging.parse("debug"));
    }

    @Test
    void sqliteKeepsTheSameRowsInEitherMode() {
        assertTrue(AppLogging.storedInSqlite(record("fel.cvut.node.Node", Level.INFO, "app-info")));
        assertTrue(AppLogging.storedInSqlite(record("fel.cvut.node.Node", Level.WARNING, "app-warn")));
        assertFalse(AppLogging.storedInSqlite(record("fel.cvut.node.Node", Level.FINE, "app-fine")));
        assertTrue(AppLogging.storedInSqlite(record("org.bouncycastle.jsse.provider.ProvTlsServer", Level.WARNING, "bc-warn")));
        assertFalse(AppLogging.storedInSqlite(record("org.bouncycastle.jsse.provider.ProvTlsServer", Level.INFO, "bc-info")));
        assertFalse(AppLogging.storedInSqlite(record("org.bouncycastle.jsse.provider.ProvTlsServer", Level.FINE, "bc-fine")));
    }

    private static LogRecord record(String logger, Level level, String message) {
        LogRecord record = new LogRecord(level, message);
        record.setLoggerName(logger);
        return record;
    }
}
