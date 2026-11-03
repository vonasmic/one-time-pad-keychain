package fel.cvut.certGen;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class CertGeneratorTest {

    private static final String PASSWORD = "changeit-test";

    @BeforeAll
    static void bc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void networkStyleFailuresCountAsHsmUnreachable() {
        assertTrue(CertGenerator.isHsmConnectionFailure(new SocketTimeoutException("read")));
        assertTrue(CertGenerator.isHsmConnectionFailure(new UnknownHostException("hsm.local")));
        assertTrue(CertGenerator.isHsmConnectionFailure(new IOException("Connection timed out")));
        assertTrue(CertGenerator.isHsmConnectionFailure(
                new RuntimeException("a", new RuntimeException("b", new IOException("connection refused")))));
    }

    @Test
    void otherFailuresAreNotHsmConnectionProblems() {
        assertFalse(CertGenerator.isHsmConnectionFailure(new RuntimeException()));
        assertFalse(CertGenerator.isHsmConnectionFailure(new IllegalStateException("Required environment variable not set: PIN")));
        assertFalse(CertGenerator.isHsmConnectionFailure(new IllegalStateException((String) null)));
        assertFalse(CertGenerator.isHsmConnectionFailure(new java.security.KeyStoreException("bad keystore")));
    }

    @Test
    void signsRawMlDsaLeafWithClientCaAndWritesPem(@TempDir Path dir) throws Exception {
        KeyPair caKeys = mlDsa();
        X500Name caName = new X500Name("CN=Test-Client-CA");
        X509Certificate caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                new JcaX509v3CertificateBuilder(caName, BigInteger.ONE, new Date(),
                        new Date(System.currentTimeMillis() + 86_400_000L), caName, caKeys.getPublic())
                        .build(new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(caKeys.getPrivate())));
        Path p12 = dir.resolve("client_ca.p12");
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        ks.setKeyEntry("ca", caKeys.getPrivate(), PASSWORD.toCharArray(), new X509Certificate[] {caCert});
        try (FileOutputStream out = new FileOutputStream(p12.toFile())) {
            ks.store(out, PASSWORD.toCharArray());
        }

        KeyPair device = mlDsa();
        byte[] rawPub = ((MLDSAPublicKey) device.getPublic()).getPublicData();
        assertEquals(1312, rawPub.length);

        X509Certificate leaf = CertGenerator.signRawMlDsa44Leaf(p12, PASSWORD, rawPub, "device-7");

        assertEquals("CN=device-7", leaf.getSubjectX500Principal().getName());
        assertEquals(caCert.getSubjectX500Principal(), leaf.getIssuerX500Principal());
        assertDoesNotThrow(() -> leaf.verify(caCert.getPublicKey(), "BC"));
        assertArrayEquals(rawPub, ((MLDSAPublicKey) leaf.getPublicKey()).getPublicData());

        Path pem = dir.resolve("out").resolve("device.pem");
        CertGenerator.writeCertPem(leaf, pem);
        String text = Files.readString(pem);
        assertTrue(text.startsWith("-----BEGIN CERTIFICATE-----\n"));
        assertTrue(text.endsWith("-----END CERTIFICATE-----\n"));
        try (FileInputStream in = new FileInputStream(pem.toFile())) {
            X509Certificate reread = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
                    .generateCertificate(in);
            assertEquals(leaf, reread);
        }
    }

    @Test
    void signRejectsWrongKeyLength(@TempDir Path dir) {
        assertThrows(IllegalArgumentException.class,
                () -> CertGenerator.signRawMlDsa44Leaf(dir.resolve("none.p12"), PASSWORD, new byte[32], "x"));
    }

    private static KeyPair mlDsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, new SecureRandom());
        return kpg.generateKeyPair();
    }
}