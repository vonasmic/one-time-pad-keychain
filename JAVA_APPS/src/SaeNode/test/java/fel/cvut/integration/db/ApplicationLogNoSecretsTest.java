package fel.cvut.integration.db;

import fel.cvut.db.*;
import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.PeerRecordSync;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.utimaco.HsmAesGcm;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Tag("integration")
@Timeout(60)
class ApplicationLogNoSecretsTest {

    private static final String MARKER = "PAD-SECRET-KEYSTREAM-9f3c-DO-NOT-LOG";
    private static final String PIN = "12345678";

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    @BeforeEach
    void installLogging() {
        SqliteLogging.close();
        SqliteLogging.install(SQLITE.originJdbcUrl());
    }

    @AfterEach
    void uninstallLogging() {
        SqliteLogging.close();
    }

    @Test
    void successfulExchangeDoesNotLogPadPinOrHsmKey() throws Exception {
        byte[] raw = new byte[Math.max(64, SaeFixtures.uplink().plainMax() * SaeFixtures.uplink().padCount())];
        byte[] markerBytes = MARKER.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(markerBytes, 0, raw, 0, markerBytes.length);
        String keyMaterial = Base64.getEncoder().encodeToString(raw);
        Qkd014Client qkd = SaeFixtures.mockQkdWithKey("key-secret", keyMaterial);
        AtomicRecordStateMap originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        NodeCommandsService peerService = SaeFixtures.commands(
                SaeFixtures.peerRef(),
                SQLITE.peer(),
                qkd,
                JceAesGcm.mockHsm()
        );
        RmiManager rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(PEER_SAE)).thenReturn(fel.cvut.harness.AsCaller.bind(ORIGIN_SAE, peerService));
        assertEquals(
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE)
        );
        assertTrue(new PeerRecordSync(SaeFixtures.originRef(), originMap, rmi, qkd)
                .completeNewExchange(SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of()), SaeFixtures.uplink())
                .keys()
                .isPresent());

        List<String> logs = readLogs();
        assertFalse(logs.isEmpty(), "application_log should record the exchange");
        String joined = String.join("\n", logs).toLowerCase(Locale.ROOT);
        assertFalse(joined.contains(MARKER.toLowerCase(Locale.ROOT)));
        assertFalse(joined.contains(keyMaterial.toLowerCase(Locale.ROOT)));
        assertFalse(joined.contains(PIN));
        assertFalse(joined.contains(HsmAesGcm.KEY_ALIAS.toLowerCase(Locale.ROOT)));
        assertFalse(joined.contains("shared-key-aes"));
    }

    private static List<String> readLogs() throws Exception {
        List<String> rows = new ArrayList<>();
        try (Connection connection = SQLITE.origin().getConnection();
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(
                     "SELECT message, thrown FROM application_log")) {
            while (resultSet.next()) {
                String message = resultSet.getString("message");
                if (message != null) {
                    rows.add(message);
                }
                String thrown = resultSet.getString("thrown");
                if (thrown != null) {
                    rows.add(thrown);
                }
            }
        }
        return rows;
    }
}
