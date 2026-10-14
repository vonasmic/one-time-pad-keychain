package fel.cvut.certGen;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Tag("unit")
class CertGenConfigTest {

    private static boolean certgenEnvUnset() {
        for (String key : List.of("CERTGEN_ROOT_CA", "CERTGEN_CLIENT_CA", "CERTGEN_NODES", "CERTGEN_ENV")) {
            String v = System.getenv(key);
            if (v != null && !v.isBlank()) {
                return false;
            }
        }
        return true;
    }

    @Test
    void tokenStripsCertExtensionsAndTrims() {
        assertEquals("node-a", CertGenConfig.token("  node-a ", "X"));
        assertEquals("root-ca", CertGenConfig.token("root-ca.pem", "X"));
        assertEquals("client_ca", CertGenConfig.token("client_ca.p12", "X"));
    }

    @Test
    void tokenRejectsPathTraversalAndEmpty() {
        for (String bad : new String[] {null, "", "   ", ".pem", "a/b", "a\\b", "..", "x..y", "nul\0l"}) {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> CertGenConfig.token(bad, "CERTGEN_NODES"), String.valueOf(bad));
            assertTrue(ex.getMessage().startsWith("Invalid CERTGEN_NODES name"));
        }
    }

    @Test
    void namesSplitsCsvAndRejectsDuplicates() {
        assertEquals(List.of(), CertGenConfig.names(null, "N"));
        assertEquals(List.of(), CertGenConfig.names("  ", "N"));
        assertEquals(List.of("a", "b", "c"), CertGenConfig.names("a, b ,c.pem", "N"));
        IllegalArgumentException dup = assertThrows(IllegalArgumentException.class,
                () -> CertGenConfig.names("a,b,a.pem", "CERTGEN_NODES"));
        assertTrue(dup.getMessage().contains("Duplicate name in CERTGEN_NODES: a"));
        assertThrows(IllegalArgumentException.class, () -> CertGenConfig.names("a,,b", "N"));
    }

    @Test
    void parseEnvFileHandlesCommentsExportQuotesAndJunk(@TempDir Path dir) throws Exception {
        Path env = dir.resolve("certgen.env");
        Files.writeString(env, String.join("\n",
                "# comment",
                "",
                "export CERTGEN_ROOT_CA=\"my-root\"",
                "CERTGEN_CLIENT_CA='my-client'",
                "CERTGEN_NODES = n1,n2",
                "no-equals-line",
                "=missingkey",
                "EMPTY=",
                "QUOTE_ONE=\"",
                "PKCS12_PASSWORD=a=b"), StandardCharsets.UTF_8);

        Map<String, String> values = CertGenConfig.parseEnvFile(env);

        assertEquals("my-root", values.get("CERTGEN_ROOT_CA"));
        assertEquals("my-client", values.get("CERTGEN_CLIENT_CA"));
        assertEquals("n1,n2", values.get("CERTGEN_NODES"));
        assertEquals("", values.get("EMPTY"));
        assertEquals("\"", values.get("QUOTE_ONE"));
        assertEquals("a=b", values.get("PKCS12_PASSWORD"));
        assertEquals(6, values.size(), values.toString());
    }

    @Test
    void fromUsesFileValuesAndDefaults() {
        assumeTrue(certgenEnvUnset());
        CertGenConfig cfg = CertGenConfig.from(Map.of("CERTGEN_NODES", "sae-1, sae-2"));
        assertEquals(CertGenConfig.DEFAULT_ROOT_CA, cfg.rootCaName());
        assertEquals(CertGenConfig.DEFAULT_CLIENT_CA, cfg.clientCaName());
        assertEquals(List.of("sae-1", "sae-2"), cfg.nodes());

        CertGenConfig custom = CertGenConfig.from(Map.of(
                "CERTGEN_ROOT_CA", "r.p12", "CERTGEN_CLIENT_CA", " c ", "CERTGEN_NODES", "n"));
        assertEquals("r", custom.rootCaName());
        assertEquals("c", custom.clientCaName());
    }

    @Test
    void fromRejectsEmptyNodesAndIdenticalCas() {
        assumeTrue(certgenEnvUnset());
        IllegalStateException empty = assertThrows(IllegalStateException.class, () -> CertGenConfig.from(Map.of()));
        assertTrue(empty.getMessage().startsWith("CERTGEN_NODES is empty"));
        IllegalStateException same = assertThrows(IllegalStateException.class, () -> CertGenConfig.from(Map.of(
                "CERTGEN_ROOT_CA", "ca", "CERTGEN_CLIENT_CA", "ca.pem", "CERTGEN_NODES", "n")));
        assertTrue(same.getMessage().contains("must differ"));
    }


    @Test
    void envFilePathDefaultsAndMissingFileYieldsEmptyValues() throws Exception {
        assumeTrue(certgenEnvUnset());
        assertEquals(Path.of(CertGenConfig.DEFAULT_ENV_FILE), CertGenConfig.envFilePath());
        assumeTrue(!Files.isRegularFile(CertGenConfig.envFilePath()), "a real env/certgen.env exists in cwd");
        assertEquals(Map.of(), CertGenConfig.loadFileValues());
    }
}