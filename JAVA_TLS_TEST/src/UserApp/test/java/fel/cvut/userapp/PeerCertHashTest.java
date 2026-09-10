package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PeerCertHashTest {

    @BeforeAll
    static void addBc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void hashIsSha384OfRawSubjectPublicKeyBitsNotFullSpkiDer() throws Exception {
        X509Certificate cert = selfSignedP256("CN=peer-hash-test");
        byte[] bits = new X509CertificateHolder(cert.getEncoded())
                .getSubjectPublicKeyInfo()
                .getPublicKeyData()
                .getBytes();
        String expected = SeBytes.toHex(SeBytes.sha384(bits));
        assertEquals(expected, PeerCertHash.hashHex(cert));
        assertEquals(96, expected.length());

        String fullSpkiHash = SeBytes.toHex(SeBytes.sha384(cert.getPublicKey().getEncoded()));
        assertNotEquals(fullSpkiHash, expected);
    }

    @Test
    void hashFromPemPathMatchesInMemoryCert(@TempDir Path tmp) throws Exception {
        X509Certificate cert = selfSignedP256("CN=peer-pem");
        Path pem = writePem(tmp.resolve("peer.pem"), cert);
        assertEquals(PeerCertHash.hashHex(cert), PeerCertHash.hashHex(pem));
    }

    @Test
    void parseHashHexAccepts96Hex() {
        String hex = "0123456789abcdef0123456789abcdef0123456789abcdef"
                + "0123456789abcdef0123456789abcdef0123456789abcdef";
        assertEquals(hex, PeerCertHash.parseHashHex(hex));
        assertEquals(hex, PeerCertHash.parseHashHex(hex.toUpperCase(Locale.ROOT)));
    }

    @Test
    void parseHashHexRejectsCertNamesAndBadLength() {
        assertThrows(IllegalArgumentException.class, () -> PeerCertHash.parseHashHex("client2"));
        assertThrows(IllegalArgumentException.class, () -> PeerCertHash.parseHashHex("abc"));
        assertThrows(IllegalArgumentException.class, () -> PeerCertHash.parseHashHex(""));
    }

    @Test
    void nicknameRulesMatchFirmware() {
        assertTrue(PeerCertHash.validNickname("Alice"));
        assertTrue(PeerCertHash.validNickname("a_b-c.1"));
        assertFalse(PeerCertHash.validNickname(""));
        assertFalse(PeerCertHash.validNickname("has space"));
        assertFalse(PeerCertHash.validNickname("this-name-is-17ch"));
    }

    @Test
    void pythonStyleBitStringSkipUnusedBitsByte() throws Exception {
        X509Certificate cert = selfSignedP256("CN=bitstring");
        ASN1BitString bitString = new X509CertificateHolder(cert.getEncoded())
                .getSubjectPublicKeyInfo()
                .getPublicKeyData();
        assertEquals(0, bitString.getPadBits());
        assertEquals(
                SeBytes.toHex(SeBytes.sha384(bitString.getBytes())),
                PeerCertHash.hashHex(cert));
    }

    @Test
    void alicePemMatchesEmbedFwCredsRawSpkiLengthWhenPresent() throws Exception {
        Path alice = Path.of("certs/Alice.pem");
        assumeTrue(Files.isRegularFile(alice), "certs/Alice.pem not in working directory");
        X509Certificate cert = PeerCertHash.loadCert(alice);
        byte[] bits = PeerCertHash.rawSpkiBits(cert);
        assertEquals(1312, bits.length);
        assertEquals(SeBytes.toHex(SeBytes.sha384(bits)), PeerCertHash.hashHex(alice));
        assertNotEquals(
                SeBytes.toHex(SeBytes.sha384(cert.getPublicKey().getEncoded())),
                PeerCertHash.hashHex(alice));
    }

    private static Path writePem(Path pem, X509Certificate cert) throws Exception {
        Files.createDirectories(pem.getParent() == null ? Path.of(".") : pem.getParent());
        try (var writer = new JcaPEMWriter(Files.newBufferedWriter(pem))) {
            writer.writeObject(cert);
        }
        return pem;
    }

    private static X509Certificate selfSignedP256(String dn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();
        Date now = new Date();
        Date until = new Date(now.getTime() + 86_400_000L);
        X500Name name = new X500Name(dn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, now, until, name, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(kp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }
}
