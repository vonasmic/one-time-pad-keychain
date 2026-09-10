package fel.cvut.utimaco;

import fel.cvut.tls.NodeTls;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("hsm")
@EnabledIfEnvironmentVariable(named = "HSM_DEVICE", matches = ".+")
@Timeout(60)
class HsmLiveNoFallbackTest {

    @Test
    void encryptDecryptRoundTripOnCryptoServer() throws Exception {
        try (Pqmi pqmi = Pqmi.fromEnvironment()) {
            NodeTls.install(pqmi);
            HsmAesGcm hsm = new HsmAesGcm();
            byte[] plaintext = "sae-hsm-roundtrip".getBytes(StandardCharsets.UTF_8);
            HsmAesGcm.SealedBlob sealed = hsm.encrypt(plaintext);
            assertNotEquals("BC", sealed.hsmKeyAlias());
            assertArrayEquals(plaintext, hsm.decrypt(sealed));
        }
    }

    @Test
    void missingAliasDoesNotFallBackToInMemoryAes() throws Exception {
        try (Pqmi pqmi = Pqmi.fromEnvironment()) {
            NodeTls.install(pqmi);
            HsmAesGcm hsm = new HsmAesGcm("missing-shared-key-aes");
            HsmAesGcm.SealedBlob sealed = new HsmAesGcm.SealedBlob(
                    new byte[32],
                    new byte[HsmAesGcm.GCM_IV_LENGTH],
                    HsmAesGcm.GCM_TAG_BITS,
                    "missing-shared-key-aes"
            );
            assertThrows(Exception.class, () -> hsm.decrypt(sealed));
        }
    }
}
