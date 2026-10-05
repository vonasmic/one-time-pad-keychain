package fel.cvut.utimaco;

import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.tls.HsmNodeTls;
import fel.cvut.tls.SoftwareTls;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Timeout(60)
class HsmFailClosedTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    @Test
    void storeWriteDoesNotPersistWhenEncryptFails() throws Exception {
        HsmAesGcm hsm = mock(HsmAesGcm.class);
        when(hsm.encrypt(any())).thenThrow(new IllegalStateException("HSM unavailable"));
        SharedKeyMaterialStore store = SaeFixtures.keyStore(SQLITE.origin(), hsm);
        AtomicRecordStateMap stateMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
        ClientRecord record = SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, java.util.List.of("secret"));
        stateMap.synchronize(record.getClientHeader(), ORIGIN_SAE);

        assertThrows(IOException.class, () -> store.write(record));
        assertEquals(0, SaeFixtures.countKeyMaterial(SQLITE.origin()));
    }

    @Test
    void encryptWithoutCryptoServerDoesNotFallBackToSoftwareAes() {
        try {
            HsmNodeTls.requireCryptoServer();
            Assumptions.abort("CryptoServer already installed in this JVM");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("CryptoServer not installed"));
        }

        Exception thrown = assertThrows(Exception.class, () -> new HsmAesGcm().encrypt("no-fallback".getBytes()));
        Throwable cursor = thrown;
        boolean sawCryptoServer = false;
        while (cursor != null) {
            if (cursor.getMessage() != null && cursor.getMessage().contains("CryptoServer")) {
                sawCryptoServer = true;
                break;
            }
            cursor = cursor.getCause();
        }
        assertTrue(sawCryptoServer, "Expected CryptoServer failure, got: " + thrown);
    }
}
