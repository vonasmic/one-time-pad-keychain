package fel.cvut.unit.terminal;

import fel.cvut.terminal.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;

import java.util.logging.Level;
import java.util.logging.LogRecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
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

    @Test
    void terminalLineIsLevelMessageAndExceptionMessage() {
        LogRecord plain = record("fel.cvut.node.Node", Level.WARNING, "USB provision session ended");
        assertEquals("WARNING: USB provision session ended", AppLogging.terminalLine(plain));

        LogRecord withCause = record("fel.cvut.node.Node", Level.SEVERE, "Failed to start node");
        withCause.setThrown(new IllegalStateException("HSM_DEVICE is not set"));
        assertEquals("SEVERE: Failed to start node: IllegalStateException: HSM_DEVICE is not set",
                AppLogging.terminalLine(withCause));

        LogRecord repeated = record("fel.cvut.node.Node", Level.SEVERE,
                "Invalid node environment: Required environment variable is not set: SAE_ID");
        repeated.setThrown(new IllegalStateException("Required environment variable is not set: SAE_ID"));
        assertEquals("SEVERE: Invalid node environment: Required environment variable is not set: SAE_ID",
                AppLogging.terminalLine(repeated));

        LogRecord noDetail = record("fel.cvut.node.Node", Level.SEVERE, "Socket failed");
        noDetail.setThrown(new NullPointerException());
        assertEquals("SEVERE: Socket failed (NullPointerException)", AppLogging.terminalLine(noDetail));
    }

    @Test
    void terminalPrintsErrorsOnly() {
        LogRecord noise = record("org.bouncycastle.jsse.provider.DisabledAlgorithmConstraints", Level.WARNING,
                "Ignoring unsupported entry in 'jdk.tls.disabledAlgorithms': ecdsa_sha1 usage HandshakeSignature");
        assertFalse(AppLogging.shownOnTerminal(noise));
        assertTrue(AppLogging.storedInSqlite(noise));

        assertFalse(AppLogging.shownOnTerminal(
                record("fel.cvut.node.Node", Level.WARNING, "USB provision session ended: port closed")));
        assertFalse(AppLogging.shownOnTerminal(record("fel.cvut.node.Node", Level.INFO, "Node started")));
        assertTrue(AppLogging.shownOnTerminal(
                record("fel.cvut.node.Node", Level.SEVERE, "Failed to start node")));
    }

    private static LogRecord record(String logger, Level level, String message) {
        LogRecord record = new LogRecord(level, message);
        record.setLoggerName(logger);
        return record;
    }
}
