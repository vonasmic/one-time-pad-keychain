package fel.cvut.certGen;

import org.junit.jupiter.api.Test;

import java.net.ConnectException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertGeneratorHsmFallbackTest {

    @Test
    void treatsUtimacoNoConnectionAsConnectionFailure() {
        RuntimeException thrown = new RuntimeException(
                "HSM::ConnectionException(Error::NO_CONNECTION = 0xbe000015) thrown in open_session");
        assertTrue(CertGenerator.isHsmConnectionFailure(thrown));
    }

    @Test
    void treatsConnectExceptionCauseAsConnectionFailure() {
        assertTrue(CertGenerator.isHsmConnectionFailure(
                new RuntimeException("provider build failed", new ConnectException("Connection refused"))));
    }

    @Test
    void treatsMissingHsmEnvAsConnectionFailure() {
        assertTrue(CertGenerator.isHsmConnectionFailure(
                new IllegalStateException("Required environment variable not set: HSM_DEVICE")));
    }

    @Test
    void doesNotTreatWrongPinAsConnectionFailure() {
        assertFalse(CertGenerator.isHsmConnectionFailure(
                new IllegalStateException("login failed: invalid PIN")));
    }
}
