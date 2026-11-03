package fel.cvut.unit.node;

import fel.cvut.node.Address;
import fel.cvut.node.interNodeCommunication.KnownPeers;
import fel.cvut.node.interNodeCommunication.SaeNodes;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SAE directory ({@code SAE_NODES_FILE}): loader, validation, own-pin and file-permission checks. */
@Tag("unit")
class SaeNodesTest {

    private static final String PIN_1 = "1".repeat(96);
    private static final String PIN_2 = "2".repeat(96);

    private static String row(String saeId, String name, String location, String hostname, int port, String pin) {
        return "{ \"saeId\": \"" + saeId + "\", \"name\": \"" + name + "\", \"location\": \"" + location
                + "\", \"hostname\": \"" + hostname + "\", \"port\": " + port + ", \"spkiSha384\": \"" + pin + "\" }";
    }

    private static final String SAE_1 = row("sae-1", "Alice", "Prague", "127.0.0.1", 2010, PIN_1);
    private static final String SAE_2 = row("sae-2", "Bob", "Berlin", "127.0.0.1", 2020, PIN_2);

    private static Path write(Path dir, String file, String... rows) throws IOException {
        Path p = dir.resolve(file);
        Files.writeString(p, "[\n  " + String.join(",\n  ", rows) + "\n]\n");
        if (posix(dir)) {
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-r--r--"));
        }
        return p;
    }

    private static boolean posix(Path dir) {
        return Files.getFileAttributeView(dir, PosixFileAttributeView.class) != null;
    }

    @Test
    void loadsDirectoryAndDerivesOwnNamePortAndHostname(@TempDir Path dir) throws Exception {
        SaeNodes nodes = SaeNodes.loadTrusted(write(dir, "sae-nodes.json", SAE_1, SAE_2));
        assertEquals(List.of("sae-1", "sae-2"), nodes.entries().stream().map(SaeNodes.Entry::saeId).toList());
        SaeNodes.Entry self = nodes.self("sae-2");
        assertEquals("Bob", self.name());
        assertEquals("Berlin", self.location());
        assertEquals(new Address("127.0.0.1", 2020), self.address());
        assertEquals(PIN_2, self.spkiSha384());
        IllegalStateException missing = assertThrows(IllegalStateException.class, () -> nodes.self("sae-3"));
        assertTrue(missing.getMessage().contains("sae-3"), missing.getMessage());
    }

    @Test
    void rejectsMalformedEntries(@TempDir Path dir) throws Exception {
        List<String> fields = List.of("\"saeId\": \"sae-1\"", "\"name\": \"Alice\"", "\"location\": \"Prague\"",
                "\"hostname\": \"127.0.0.1\"", "\"port\": 2010", "\"spkiSha384\": \"" + PIN_1 + "\"");
        assertEquals(SAE_1, "{ " + String.join(", ", fields) + " }");
        for (int i = 0; i < fields.size(); i++) {
            List<String> rest = new java.util.ArrayList<>(fields);
            String dropped = rest.remove(i);
            Path p = write(dir, "missing-" + i + ".json", "{ " + String.join(", ", rest) + " }");
            assertThrows(IllegalArgumentException.class, () -> SaeNodes.load(p), "missing " + dropped);
        }
        List<String> bad = List.of(
                row(" ", "Alice", "Prague", "127.0.0.1", 2010, PIN_1),
                row("sae-1", "../Alice", "Prague", "127.0.0.1", 2010, PIN_1),
                row("sae-1", "Alice", "Prague", "127.0.0.1", 0, PIN_1),
                row("sae-1", "Alice", "Prague", "127.0.0.1", 65536, PIN_1),
                row("sae-1", "Alice", "Prague", "127.0.0.1", 2010, "abcd"),
                row("sae-1", "Alice", "Prague", "127.0.0.1", 2010, "A".repeat(96)),
                row("sae-1", "Alice", "Prague", "127.0.0.1", 2010, "z".repeat(96)));
        for (int i = 0; i < bad.size(); i++) {
            Path p = write(dir, "bad-" + i + ".json", bad.get(i));
            assertThrows(IllegalArgumentException.class, () -> SaeNodes.load(p), bad.get(i));
        }
        Path extra = write(dir, "extra.json", SAE_1.replace(" }", ", \"extra\": 1 }"));
        assertThrows(IOException.class, () -> SaeNodes.load(extra), "unknown field");
        Path notArray = dir.resolve("object.json");
        Files.writeString(notArray, SAE_1);
        assertThrows(IOException.class, () -> SaeNodes.load(notArray));
    }

    @Test
    void rejectsDuplicateIdsNamesPinsAndEndpoints(@TempDir Path dir) throws Exception {
        List<String> clashes = List.of(
                row("sae-1", "Bob", "Berlin", "127.0.0.1", 2020, PIN_2),
                row("sae-2", "alice", "Berlin", "127.0.0.1", 2020, PIN_2),
                row("sae-2", "Bob", "Berlin", "127.0.0.1", 2020, PIN_1),
                row("sae-2", "Bob", "Berlin", "127.0.0.1", 2010, PIN_2));
        for (int i = 0; i < clashes.size(); i++) {
            Path p = write(dir, "dup-" + i + ".json", SAE_1, clashes.get(i));
            assertThrows(IllegalArgumentException.class, () -> SaeNodes.load(p), clashes.get(i));
        }
        assertDoesNotThrow(() -> SaeNodes.load(write(dir, "ok.json", SAE_1,
                row("sae-2", "Bob", "Berlin", "127.0.0.1", 2011, PIN_2))));
    }

    @Test
    void refusesWritableOrIrregularFiles(@TempDir Path dir) throws Exception {
        Assumptions.assumeTrue(posix(dir), "POSIX permissions");
        Path ok = write(dir, "ok.json", SAE_1);
        assertDoesNotThrow(() -> SaeNodes.loadTrusted(ok));

        for (String perms : List.of("rw-rw-r--", "rw-r--rw-")) {
            Path p = write(dir, "w-" + perms + ".json", SAE_1);
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(perms));
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> SaeNodes.loadTrusted(p));
            assertTrue(ex.getMessage().contains("writable"), ex.getMessage());
        }

        Path writable = write(dir, "writable.json", SAE_1);
        Files.setPosixFilePermissions(writable, PosixFilePermissions.fromString("rw-rw-rw-"));
        Path linkToWritable = Files.createSymbolicLink(dir.resolve("link-writable.json"), writable);
        assertThrows(IllegalArgumentException.class, () -> SaeNodes.loadTrusted(linkToWritable));
        Path linkToOk = Files.createSymbolicLink(dir.resolve("link-ok.json"), ok);
        assertDoesNotThrow(() -> SaeNodes.loadTrusted(linkToOk));

        Path sub = Files.createDirectory(dir.resolve("sub.json"));
        assertThrows(IllegalArgumentException.class, () -> SaeNodes.loadTrusted(sub));
        assertThrows(IOException.class, () -> SaeNodes.loadTrusted(dir.resolve("absent.json")));
    }

    @Test
    void fromEnvironmentRequiresSaeNodesFile() {
        Assumptions.assumeTrue(System.getenv(SaeNodes.ENV_FILE) == null);
        IllegalStateException ex = assertThrows(IllegalStateException.class, SaeNodes::fromEnvironment);
        assertTrue(ex.getMessage().contains(SaeNodes.ENV_FILE + " is not set"), ex.getMessage());
    }

    @Test
    void ownPinMustMatchOwnLeaf() throws Exception {
        X509Certificate own = cert("CN=Alice");
        SaeNodes.Entry self = new SaeNodes.Entry("sae-1", "Alice", "Prague", new Address("127.0.0.1", 2010),
                KnownPeers.spkiSha384(own));
        assertDoesNotThrow(() -> SaeNodes.requireOwnPin(self, own, "certs/Alice.pem"));
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> SaeNodes.requireOwnPin(self, cert("CN=Alice"), "certs/Alice.pem"));
        assertTrue(ex.getMessage().contains("does not match"), ex.getMessage());
    }

    private static X509Certificate cert(String dn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair keys = kpg.generateKeyPair();
        Date now = new Date();
        X500Name name = new X500Name(dn);
        var builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, now, new Date(now.getTime() + 86_400_000L), name, keys.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }
}
