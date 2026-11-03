package fel.cvut.integration.tls;

import fel.cvut.tls.SoftwareLeaf;
import fel.cvut.tls.SoftwareTls;
import fel.cvut.tls.TlsStores;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Two SAE nodes (sae-1, sae-2) with ML-DSA-44 leaves under one software root CA, talking
 * pure-PQC mutual TLS 1.3 over loopback. Certificates are generated into a temp dir.
 */
@Tag("integration")
@Timeout(120)
class SoftwareTlsTwoNodeTest {

    private static final char[] P12_PASSWORD = "it-password".toCharArray();

    @BeforeAll
    static void providers() {
        SoftwareTls.installSoftware();
    }

    @Test
    void mutualPqcHandshakeAndApplicationDataBothDirections(@TempDir Path dir) throws Exception {
        Pki pki = Pki.create(dir);
        SSLContext node1 = SoftwareTls.createContextFromPem(pki.leafPem("sae-1"), pki.keyPem("sae-1"), pki.rootPem);
        SSLContext node2 = SoftwareTls.createContextFromPkcs12(pki.p12("sae-2"), P12_PASSWORD, pki.rootPem);

        Exchange a = echo(node1, node2, SoftwareTls.TlsProfile.PURE_PQC, "hello from sae-2");
        assertEquals("TLSv1.3", a.protocol);
        assertEquals("CN=sae-2", a.serverSawPeer);
        assertEquals("CN=sae-1", a.clientSawPeer);
        assertEquals("echo:hello from sae-2", a.reply);

        Exchange b = echo(node2, node1, SoftwareTls.TlsProfile.PURE_PQC, "hello from sae-1");
        assertEquals("CN=sae-1", b.serverSawPeer);
        assertEquals("CN=sae-2", b.clientSawPeer);
    }

    @Test
    void classicalProfileClientNegotiatesPqcWithPureServer(@TempDir Path dir) throws Exception {
        Pki pki = Pki.create(dir);
        SSLContext node1 = SoftwareTls.createContextFromPem(pki.leafPem("sae-1"), pki.keyPem("sae-1"), pki.rootPem);
        SSLContext node2 = SoftwareTls.createContextFromPem(pki.leafPem("sae-2"), pki.keyPem("sae-2"), pki.rootPem);
        Exchange ex = echo(node1, node2, SoftwareTls.TlsProfile.CLASSICAL, "x");
        assertEquals("TLSv1.3", ex.protocol);
    }

    @Test
    void nodeFromForeignCaIsRejectedByServer(@TempDir Path dir) throws Exception {
        Pki pki = Pki.create(dir.resolve("good"));
        Pki rogue = Pki.create(dir.resolve("rogue"));
        SSLContext server = SoftwareTls.createContextFromPem(pki.leafPem("sae-1"), pki.keyPem("sae-1"), pki.rootPem);
        // Rogue client trusts the real root (so it accepts the server) but its own cert is foreign.
        SSLContext client = SoftwareTls.createContextFromPem(rogue.leafPem("sae-2"), rogue.keyPem("sae-2"), pki.rootPem);
        assertHandshakeFails(server, client);
    }

    @Test
    void clientRejectsServerFromForeignCa(@TempDir Path dir) throws Exception {
        Pki pki = Pki.create(dir.resolve("good"));
        Pki rogue = Pki.create(dir.resolve("rogue"));
        SSLContext server = SoftwareTls.createContextFromPem(rogue.leafPem("sae-1"), rogue.keyPem("sae-1"), pki.rootPem);
        SSLContext client = SoftwareTls.createContextFromPem(pki.leafPem("sae-2"), pki.keyPem("sae-2"), pki.rootPem);
        assertHandshakeFails(server, client);
    }

    @Test
    void deviceLeafIssuedFromRawKeyAuthenticatesOverWrappedTransport(@TempDir Path dir) throws Exception {
        Pki pki = Pki.create(dir);
        // Device generates its key "on chip"; only the raw ML-DSA-44 public key leaves it.
        KeyPair device = mlDsa();
        byte[] rawPub = ((MLDSAPublicKey) device.getPublic()).getPublicData();
        X509Certificate deviceCert = SoftwareLeaf.signRawMlDsa44Leaf(
                pki.caP12, new String(P12_PASSWORD), rawPub, SoftwareLeaf.DEVICE_CLIENT_CN);
        Path deviceCertPem = dir.resolve("client").resolve("device.pem");
        SoftwareLeaf.writeCertPem(deviceCert, deviceCertPem);
        Path deviceKeyPem = dir.resolve("client").resolve("device-key.pem");
        writePem(deviceKeyPem, device.getPrivate());

        List<X509Certificate> parsed = TlsStores.readPemCerts(deviceCertPem);
        assertEquals(1, parsed.size());
        assertArrayEquals(deviceCert.getEncoded(), parsed.get(0).getEncoded());
        PrivateKey reread = TlsStores.readPemPrivateKey(deviceKeyPem);
        assertEquals(device.getPrivate().getAlgorithm(), reread.getAlgorithm());

        SSLContext node = SoftwareTls.createContextFromPem(pki.leafPem("sae-1"), pki.keyPem("sae-1"), pki.rootPem);
        SSLContext deviceCtx = SoftwareTls.createContextFromPem(deviceCertPem, deviceKeyPem, pki.rootPem);

        // USB-style: the node wraps an already-connected plain transport as TLS server.
        try (ServerSocket plain = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<String> serverSide = CompletableFuture.supplyAsync(() -> {
                try (Socket transport = plain.accept();
                     SSLSocket tls = SoftwareTls.wrapServer(node, transport)) {
                    tls.startHandshake();
                    String peer = ((X509Certificate) tls.getSession().getPeerCertificates()[0])
                            .getSubjectX500Principal().getName();
                    new DataOutputStream(tls.getOutputStream()).writeUTF("hi " + peer);
                    tls.getOutputStream().flush();
                    return peer;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            try (Socket raw = new Socket(InetAddress.getLoopbackAddress(), plain.getLocalPort());
                 SSLSocket tls = (SSLSocket) deviceCtx.getSocketFactory()
                         .createSocket(raw, "localhost", raw.getPort(), true)) {
                tls.setUseClientMode(true);
                tls.setSSLParameters(SoftwareTls.parameters(SoftwareTls.TlsProfile.PURE_PQC));
                tls.startHandshake();
                assertEquals("hi CN=" + SoftwareLeaf.DEVICE_CLIENT_CN,
                        new DataInputStream(tls.getInputStream()).readUTF());
            }
            assertEquals("CN=" + SoftwareLeaf.DEVICE_CLIENT_CN, serverSide.get(30, TimeUnit.SECONDS));
        }
    }

    @Test
    void trustStoreHelpersRoundTrip(@TempDir Path dir) throws Exception {
        Pki pki = Pki.create(dir);
        X509Certificate root = TlsStores.readPemCerts(pki.rootPem).get(0);
        KeyStore trust = TlsStores.trustStoreFromCert(root, pki.rootPem);
        assertEquals(1, trust.size());
        KeyStore p12 = TlsStores.loadPkcs12(pki.p12("sae-2"), P12_PASSWORD);
        X509Certificate leaf = TlsStores.leafFromPkcs12(p12, pki.p12("sae-2"));
        assertEquals("CN=sae-2", leaf.getSubjectX500Principal().getName());
        leaf.verify(root.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
    }

    // ---------------------------------------------------------------- helpers

    private record Exchange(String protocol, String serverSawPeer, String clientSawPeer, String reply) {
    }

    private static Exchange echo(SSLContext serverCtx, SSLContext clientCtx, SoftwareTls.TlsProfile clientProfile,
                                 String message) throws Exception {
        try (SSLServerSocket server = SoftwareTls.createServerSocket(
                0, serverCtx, SoftwareTls.TlsProfile.PURE_PQC, true, InetAddress.getLoopbackAddress())) {
            CompletableFuture<String> serverPeer = CompletableFuture.supplyAsync(() -> {
                try (SSLSocket s = (SSLSocket) server.accept()) {
                    DataInputStream in = new DataInputStream(s.getInputStream());
                    String got = in.readUTF();
                    new DataOutputStream(s.getOutputStream()).writeUTF("echo:" + got);
                    s.getOutputStream().flush();
                    return ((X509Certificate) s.getSession().getPeerCertificates()[0])
                            .getSubjectX500Principal().getName();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            try (SSLSocket client = SoftwareTls.createClientSocket(
                    "127.0.0.1", server.getLocalPort(), clientCtx, clientProfile)) {
                new DataOutputStream(client.getOutputStream()).writeUTF(message);
                client.getOutputStream().flush();
                String reply = new DataInputStream(client.getInputStream()).readUTF();
                String clientPeer = ((X509Certificate) client.getSession().getPeerCertificates()[0])
                        .getSubjectX500Principal().getName();
                return new Exchange(client.getSession().getProtocol(), serverPeer.get(30, TimeUnit.SECONDS),
                        clientPeer, reply);
            }
        }
    }

    private static void assertHandshakeFails(SSLContext serverCtx, SSLContext clientCtx) throws Exception {
        try (SSLServerSocket server = SoftwareTls.createServerSocket(
                0, serverCtx, SoftwareTls.TlsProfile.PURE_PQC, true, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Void> serverSide = CompletableFuture.runAsync(() -> {
                try (SSLSocket s = (SSLSocket) server.accept()) {
                    s.startHandshake();
                    s.getInputStream().read();
                } catch (IOException expected) {
                    // handshake failure on the server side is fine
                }
            });
            assertThrows(IOException.class, () -> {
                try (SSLSocket client = SoftwareTls.createClientSocket(
                        "127.0.0.1", server.getLocalPort(), clientCtx, SoftwareTls.TlsProfile.PURE_PQC)) {
                    // TLS 1.3 client auth failures surface on first read
                    client.getOutputStream().write(1);
                    client.getOutputStream().flush();
                    if (client.getInputStream().read() < 0) {
                        throw new IOException("server closed connection");
                    }
                }
            });
            serverSide.get(30, TimeUnit.SECONDS);
        }
    }

    private record Pki(Path dir, Path rootPem, Path caP12, KeyPair rootKeys, X509Certificate root) {

        static Pki create(Path dir) throws Exception {
            Files.createDirectories(dir);
            KeyPair rootKeys = mlDsa();
            X500Name name = new X500Name("CN=it-root-" + dir.getFileName());
            JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, new Date(),
                    new Date(System.currentTimeMillis() + 86_400_000L), name, rootKeys.getPublic());
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            X509Certificate root = cert(b, rootKeys.getPrivate());
            Path rootPem = dir.resolve("root-ca.pem");
            writePem(rootPem, root);
            Path caP12 = dir.resolve("ca.p12");
            KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            ks.load(null, null);
            ks.setKeyEntry("ca", rootKeys.getPrivate(), P12_PASSWORD, new Certificate[] {root});
            try (OutputStream out = Files.newOutputStream(caP12)) {
                ks.store(out, P12_PASSWORD);
            }
            Pki pki = new Pki(dir, rootPem, caP12, rootKeys, root);
            pki.issue("sae-1");
            pki.issue("sae-2");
            return pki;
        }

        void issue(String node) throws Exception {
            KeyPair keys = mlDsa();
            JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(root,
                    BigInteger.valueOf(System.nanoTime()), new Date(),
                    new Date(System.currentTimeMillis() + 86_400_000L), new X500Name("CN=" + node), keys.getPublic());
            X509Certificate leaf = cert(b, rootKeys.getPrivate());
            writePem(leafPem(node), leaf);
            writePem(keyPem(node), keys.getPrivate());
            KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            ks.load(null, null);
            ks.setKeyEntry(node, keys.getPrivate(), P12_PASSWORD, new Certificate[] {leaf, root});
            try (OutputStream out = Files.newOutputStream(p12(node))) {
                ks.store(out, P12_PASSWORD);
            }
        }

        Path leafPem(String node) {
            return dir.resolve(node + ".pem");
        }

        Path keyPem(String node) {
            return dir.resolve(node + "-key.pem");
        }

        Path p12(String node) {
            return dir.resolve(node + ".p12");
        }
    }

    private static X509Certificate cert(JcaX509v3CertificateBuilder b, PrivateKey signer) throws Exception {
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                b.build(new JcaContentSignerBuilder(signer.getAlgorithm())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signer)));
    }

    private static KeyPair mlDsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44);
        return kpg.generateKeyPair();
    }

    private static void writePem(Path path, Object object) throws IOException {
        Files.createDirectories(path.getParent());
        try (JcaPEMWriter w = new JcaPEMWriter(Files.newBufferedWriter(path, StandardCharsets.US_ASCII))) {
            w.writeObject(object);
        }
    }
}