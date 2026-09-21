package fel.cvut.tls;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class NodeTlsSoftwareIdentityTest {

    private static final char[] PASSWORD = "password".toCharArray();

    @BeforeAll
    static void installSoftware() {
        SoftwareTls.installSoftware();
    }

    @Test
    void pkcs12AndPemLeavesMatch(@TempDir Path tmp) throws Exception {
        Fixture fx = Fixture.write(tmp);
        X509Certificate fromPem = SoftwareTls.softwareLeafFromPem(fx.certPem);
        X509Certificate fromP12 = SoftwareTls.softwareLeafFromPkcs12(fx.p12, PASSWORD);
        assertArrayEquals(fromPem.getEncoded(), fromP12.getEncoded());
        assertArrayEquals(fx.leaf.getEncoded(), fromPem.getEncoded());
    }

    @Test
    void pemAndPkcs12ContextsHandshake(@TempDir Path tmp) throws Exception {
        Fixture fx = Fixture.write(tmp);
        SSLContext pem = SoftwareTls.createContextFromPem(fx.certPem, fx.keyPem, fx.caPem);
        SSLContext p12 = SoftwareTls.createContextFromPkcs12(fx.p12, PASSWORD, fx.caPem);
        handshake(p12, pem);
        handshake(pem, p12);
    }

    @Test
    void missingPkcs12FailsClosed(@TempDir Path tmp) {
        Path missing = tmp.resolve("absent.p12");
        assertThrows(IllegalStateException.class,
                () -> SoftwareTls.createContextFromPkcs12(missing, PASSWORD, tmp.resolve("ca.pem")));
        assertThrows(IllegalStateException.class,
                () -> SoftwareTls.softwareLeafFromPkcs12(missing, PASSWORD));
    }

    private static void handshake(SSLContext serverCtx, SSLContext clientCtx) throws Exception {
        try (SSLServerSocket server = SoftwareTls.createServerSocket(
                0, serverCtx, SoftwareTls.TlsProfile.PURE_PQC, true, InetAddress.getLoopbackAddress())) {
            int port = server.getLocalPort();
            AtomicReference<Throwable> serverError = new AtomicReference<>();
            Thread acceptor = Thread.ofVirtual().unstarted(() -> {
                try (SSLSocket accepted = (SSLSocket) server.accept()) {
                    accepted.startHandshake();
                    assertEquals("TLSv1.3", accepted.getSession().getProtocol());
                } catch (Throwable t) {
                    serverError.set(t);
                }
            });
            acceptor.start();
            try (SSLSocket client = SoftwareTls.createClientSocket(
                    "127.0.0.1", port, clientCtx, SoftwareTls.TlsProfile.PURE_PQC)) {
                assertEquals("TLSv1.3", client.getSession().getProtocol());
            }
            acceptor.join();
            Throwable err = serverError.get();
            if (err instanceof Exception e) {
                throw e;
            }
            if (err instanceof Error e) {
                throw e;
            }
            if (err != null) {
                throw new IOException(err);
            }
        }
    }

    private record Fixture(Path certPem, Path keyPem, Path caPem, Path p12, X509Certificate leaf) {
        static Fixture write(Path dir) throws Exception {
            KeyPair caKeys = mlDsa();
            X509Certificate ca = selfSignedCa(caKeys, "CN=software-test-ca");
            KeyPair leafKeys = mlDsa();
            X509Certificate leaf = issueLeaf(ca, caKeys.getPrivate(), leafKeys, "CN=otp-user");

            Path certPem = dir.resolve("user-cert.pem");
            Path keyPem = dir.resolve("user-key.pem");
            Path caPem = dir.resolve("client_ca.pem");
            Path p12 = dir.resolve("user.p12");
            writePem(certPem, leaf);
            writePem(keyPem, leafKeys.getPrivate());
            writePem(caPem, ca);
            writePkcs12(p12, leafKeys.getPrivate(), leaf, ca);
            return new Fixture(certPem, keyPem, caPem, p12, leaf);
        }
    }

    private static KeyPair mlDsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44);
        return kpg.generateKeyPair();
    }

    private static X509Certificate selfSignedCa(KeyPair keys, String dn) throws Exception {
        Date now = new Date();
        X500Name name = new X500Name(dn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, now, new Date(now.getTime() + 86_400_000L), name, keys.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(keys.getPrivate().getAlgorithm())
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keys.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    private static X509Certificate issueLeaf(
            X509Certificate ca, PrivateKey caKey, KeyPair leafKeys, String dn
    ) throws Exception {
        Date now = new Date();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                ca, BigInteger.valueOf(2), now, new Date(now.getTime() + 86_400_000L),
                new X500Name(dn), leafKeys.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(caKey.getAlgorithm())
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caKey);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    private static void writePem(Path path, Object pemObject) throws IOException {
        try (var writer = new JcaPEMWriter(Files.newBufferedWriter(path))) {
            writer.writeObject(pemObject);
        }
    }

    private static void writePkcs12(Path p12, PrivateKey key, X509Certificate leaf, X509Certificate ca)
            throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        ks.load(null, null);
        ks.setKeyEntry("user", key, PASSWORD, new Certificate[]{leaf, ca});
        try (OutputStream out = Files.newOutputStream(p12)) {
            ks.store(out, PASSWORD);
        }
    }
}
