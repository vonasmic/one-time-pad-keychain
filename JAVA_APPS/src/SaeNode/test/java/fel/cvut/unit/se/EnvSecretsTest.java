package fel.cvut.unit.se;

import fel.cvut.se.EnvSecrets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Tag("unit")
class EnvSecretsTest {

    /** Names that must not exist in the test JVM environment. */
    private static final String UNSET_A = "OTP_ENVSECRETS_TEST_UNSET_A";
    private static final String UNSET_B = "OTP_ENVSECRETS_TEST_UNSET_B";

    private InputStream originalIn;

    @BeforeEach
    void setUp() {
        assumeTrue(System.getenv(UNSET_A) == null && System.getenv(UNSET_B) == null);
        originalIn = System.in;
    }

    @AfterEach
    void restore() {
        if (originalIn != null) {
            System.setIn(originalIn);
        }
    }


    @Test
    void processEnvironmentWinsOverFileValues() {
        String path = System.getenv("PATH");
        assumeTrue(path != null && !path.isBlank());
        assertEquals(path.trim(), EnvSecrets.envOrScan(Map.of("PATH", "from-file"), "PATH"));
        assertEquals(path.trim(), EnvSecrets.envOrScan(UNSET_A, "PATH"));
    }

    @Test
    void fileValuesUsedWhenEnvMissingAndAreTrimmed() {
        Map<String, String> file = new HashMap<>();
        file.put(UNSET_A, "   ");
        file.put(UNSET_B, "  secret-from-file  ");
        assertEquals("secret-from-file", EnvSecrets.envOrScan(file, UNSET_A, UNSET_B));
    }

    @Test
    void withoutConsoleFailsClearlyAndNeverReadsStdin() throws Exception {
        assumeTrue(System.console() == null, "needs a non-interactive JVM");
        byte[] typed = "typed-secret\nnext\n".getBytes(StandardCharsets.US_ASCII);
        ByteArrayInputStream stdin = new ByteArrayInputStream(typed);
        System.setIn(stdin);
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> EnvSecrets.envOrScan(UNSET_A));
        assertTrue(ex.getMessage().contains(UNSET_A), ex.getMessage());
        assertTrue(ex.getMessage().contains("no interactive console"), ex.getMessage());
        assertEquals(typed.length, stdin.available(), "stdin must not be consumed (F-13: no echoed secret)");
    }

    @Test
    void blankFileValueStillFailsWithoutConsole() {
        assumeTrue(System.console() == null, "needs a non-interactive JVM");
        System.setIn(new ByteArrayInputStream("\n".getBytes(StandardCharsets.US_ASCII)));
        assertThrows(IllegalStateException.class, () -> EnvSecrets.envOrScan(Map.of(UNSET_A, ""), UNSET_A));
    }
}
