package fel.cvut.integration.utimaco;

import fel.cvut.tls.HsmNodeTls;
import fel.cvut.tls.SoftwareTls;
import fel.cvut.tls.TlsStores;
import fel.cvut.utimaco.HsmAesGcm;
import fel.cvut.utimaco.Pqmi;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Exercises {@link Pqmi}, {@link HsmAesGcm} and {@link HsmNodeTls} against a running Utimaco
 * CryptoServer simulator. Needs the usual HSM env ({@code HSM_DEVICE=port@host}, HSM_TIMEOUT_MS,
 * HSM_USER, HSM_PIN, HSM_MLDSA_GROUP, HSM_MLDSA_SPEC); skips (assumption) when HSM_DEVICE is unset
 * or its host:port is not accepting TCP connections. Only creates keys with an {@code it-sim-}
 * prefix so existing simulator state is left alone.
 */
@Tag("hsm")
@Tag("integration")
@Timeout(180)
class HsmSimulatorTest {

    private static final String NODE = "it-sim-node";
    private static final String AES_ALIAS = "it-sim-aes";

    private static Pqmi pqmi;
    private static String previousCertsDir;

    @BeforeAll
    static void connect() throws Exception {
        String device = System.getenv("HSM_DEVICE");
        assumeTrue(device != null && !device.isBlank(), "HSM_DEVICE not set - simulator tests skipped");
        assumeTrue(reachable(device), "HSM simulator " + device + " not reachable - skipped");
        pqmi = Pqmi.fromEnvironment();
        SoftwareTls.installSoftware();
        HsmNodeTls.install(pqmi);
        previousCertsDir = System.getProperty("pqc.certs.dir");
    }

    @AfterAll
    static void disconnect() {
        if (previousCertsDir == null) {
            System.clearProperty("pqc.certs.dir");
        } else {
            System.setProperty("pqc.certs.dir", previousCertsDir);
        }
        if (pqmi != null) {
            pqmi.close();
        }
    }

    @Test
    void aesGcmRoundTripUsesHsmKey() throws Exception {
        HsmAesGcm hsm = new HsmAesGcm(AES_ALIAS);
        hsm.ensureKey();
        hsm.ensureKey(); // idempotent
        byte[] plain = "one-time-pad chunk".getBytes(StandardCharsets.UTF_8);
        HsmAesGcm.SealedBlob a = hsm.encrypt(plain);
        HsmAesGcm.SealedBlob b = hsm.encrypt(plain);
        assertEquals(AES_ALIAS, a.hsmKeyAlias());
        assertFalse(java.util.Arrays.equals(a.gcmIv(), b.gcmIv()), "fresh IV per encryption");
        assertNotEquals(new String(a.ciphertext(), StandardCharsets.ISO_8859_1),
                new String(b.ciphertext(), StandardCharsets.ISO_8859_1));
        assertArrayEquals(plain, hsm.decrypt(a));
        assertArrayEquals(plain, hsm.decrypt(b));
    }

    @Test
    void aesGcmDetectsTamperingAndUnknownAlias() throws Exception {
        HsmAesGcm hsm = new HsmAesGcm(AES_ALIAS);
        HsmAesGcm.SealedBlob sealed = hsm.encrypt(new byte[]{1, 2, 3, 4});
        byte[] ct = sealed.ciphertext().clone();
        ct[0] ^= 1;
        HsmAesGcm.SealedBlob tampered = new HsmAesGcm.SealedBlob(ct, sealed.gcmIv(), sealed.gcmTagBits(), AES_ALIAS);
        assertThrows(Exception.class, () -> hsm.decrypt(tampered));
        HsmAesGcm.SealedBlob foreign = new HsmAesGcm.SealedBlob(
                sealed.ciphertext(), sealed.gcmIv(), sealed.gcmTagBits(), "it-sim-does-not-exist");
        assertThrows(Exception.class, () -> hsm.decrypt(foreign));
    }

    @Test
    void pqmiIdentityKeySignsVerifiablyWithMlDsa44() throws Exception {
        Pqmi.KeyRef ref = pqmi.keyRefForNode(NODE);
        pqmi.generateIdentityKey(ref, true);
        assertTrue(pqmi.identityKeyExists(ref));
        assertThrows(Exception.class, () -> pqmi.generateIdentityKey(ref, false),
                "existing key must not be silently replaced");
        byte[] pk = pqmi.exportPublicKey(ref);
        assertEquals(1312, pk.length, "raw ML-DSA-44 public key");

        pqmi.loadIdentityKey(ref);
        byte[] msg = "hsm-signed".getBytes(StandardCharsets.UTF_8);
        byte[] sig = pqmi.sign(msg);
        assertTrue(verify(pk, msg, sig), "HSM signature must verify with exported key");
        assertFalse(verify(pk, "other".getBytes(StandardCharsets.UTF_8), sig));
        assertFalse(pqmi.identityKeyExists(pqmi.keyRefForNode("it-sim-absent")));
    }

    @Test
    void hsmBackedNodeCompletesPqcHandshakeWithSoftwarePeer(@TempDir Path certs) throws Exception {
        Pqmi.KeyRef ref = pqmi.keyRefForNode(NODE);
        if (!pqmi.identityKeyExists(ref)) {
            pqmi.generateIdentityKey(ref, false);
        }
        PublicKey hsmPub = KeyFactory.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME)
                .generatePublic(new X509EncodedKeySpec(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
                        new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, pqmi.exportPublicKey(ref)))
                        .getEncoded()));

        KeyPair caKeys = mlDsa();
        X500Name caName = new X500Name("CN=it-sim-root");
        JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(caName, BigInteger.ONE, new Date(),
                new Date(System.currentTimeMillis() + 86_400_000L), caName, caKeys.getPublic());
        cb.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509Certificate ca = sign(cb, caKeys.getPrivate());
        X509Certificate hsmLeaf = sign(new JcaX509v3CertificateBuilder(ca, BigInteger.TWO, new Date(),
                new Date(System.currentTimeMillis() + 86_400_000L), new X500Name("CN=" + NODE), hsmPub),
                caKeys.getPrivate());
        KeyPair swKeys = mlDsa();
        X509Certificate swLeaf = sign(new JcaX509v3CertificateBuilder(ca, BigInteger.valueOf(3), new Date(),
                new Date(System.currentTimeMillis() + 86_400_000L), new X500Name("CN=it-sim-peer"),
                swKeys.getPublic()), caKeys.getPrivate());

        System.setProperty("pqc.certs.dir", certs.toString());
        Files.createDirectories(TlsStores.rootCaPem().getParent());
        write(TlsStores.rootCaPem(), ca);
        write(TlsStores.nodeLeafPem(NODE), hsmLeaf);
        Path swCert = certs.resolve("peer.pem");
        Path swKey = certs.resolve("peer-key.pem");
        write(swCert, swLeaf);
        write(swKey, swKeys.getPrivate());

        SSLContext hsmCtx = HsmNodeTls.createContextForNode(pqmi, NODE);
        SSLContext swCtx = SoftwareTls.createContextFromPem(swCert, swKey, TlsStores.rootCaPem());

        try (SSLServerSocket server = SoftwareTls.createServerSocket(0, swCtx, SoftwareTls.TlsProfile.PURE_PQC, true)) {
            CompletableFuture<String> peer = CompletableFuture.supplyAsync(() -> {
                try (SSLSocket s = (SSLSocket) server.accept()) {
                    s.startHandshake();
                    String cn = ((X509Certificate) s.getSession().getPeerCertificates()[0])
                            .getSubjectX500Principal().getName();
                    int b = s.getInputStream().read();
                    s.getOutputStream().write(b + 1);
                    s.getOutputStream().flush();
                    return cn;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            try (SSLSocket client = SoftwareTls.createClientSocket("127.0.0.1", server.getLocalPort(), hsmCtx,
                    SoftwareTls.TlsProfile.PURE_PQC)) {
                client.getOutputStream().write(41);
                client.getOutputStream().flush();
                assertEquals(42, client.getInputStream().read());
                assertEquals("CN=it-sim-peer", ((X509Certificate) client.getSession().getPeerCertificates()[0])
                        .getSubjectX500Principal().getName());
            }
            assertEquals("CN=" + NODE, peer.get(60, TimeUnit.SECONDS));
        }
    }

    // ---------------------------------------------------------------- helpers

    static boolean reachable(String device) {
        int at = device.indexOf('@');
        String host = at < 0 ? device : device.substring(at + 1);
        int port = 288;
        if (at > 0) {
            port = Integer.parseInt(device.substring(0, at).trim());
        } else if (host.contains(":")) {
            port = Integer.parseInt(host.substring(host.lastIndexOf(':') + 1));
            host = host.substring(0, host.lastIndexOf(':'));
        }
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), 2000);
            return true;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    private static boolean verify(byte[] rawPk, byte[] msg, byte[] sig) {
        MLDSASigner v = new MLDSASigner();
        v.init(false, new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, rawPk));
        v.update(msg, 0, msg.length);
        return v.verifySignature(sig);
    }

    private static KeyPair mlDsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44);
        return kpg.generateKeyPair();
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder b, PrivateKey key) throws Exception {
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                b.build(new JcaContentSignerBuilder(key.getAlgorithm())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(key)));
    }

    private static void write(Path path, Object o) throws IOException {
        try (JcaPEMWriter w = new JcaPEMWriter(Files.newBufferedWriter(path))) {
            w.writeObject(o);
        }
    }
}