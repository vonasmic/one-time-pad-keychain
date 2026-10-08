package fel.cvut.node;

import fel.cvut.terminal.TerminalWireProtocol;
import fel.cvut.tls.SoftwareTls;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The lab owner switch restarts TerminalApp while the previous TLS session still looks connected.
 * A live session must reject the spare client without a second handshake, and a closed one must
 * be replaced so the new terminal is not stuck retrying.
 */
class TerminalGatewayTest {

    @TempDir
    static Path tmp;

    private static SSLContext ctx;

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "terminal-gateway-test");
        thread.setDaemon(true);
        return thread;
    });
    private TerminalGateway gateway;
    private int port;

    @BeforeAll
    static void identity() throws Exception {
        SoftwareTls.installSoftware();
        KeyPair caKeys = mlDsa();
        X509Certificate ca = selfSignedCa(caKeys, "CN=gateway-test-ca");
        KeyPair leafKeys = mlDsa();
        X509Certificate leaf = issueLeaf(ca, caKeys.getPrivate(), leafKeys, "CN=otp-user");
        Path certPem = tmp.resolve("cert.pem");
        Path keyPem = tmp.resolve("key.pem");
        Path caPem = tmp.resolve("ca.pem");
        writePem(certPem, leaf);
        writePem(keyPem, leafKeys.getPrivate());
        writePem(caPem, ca);
        ctx = SoftwareTls.createContextFromPem(certPem, keyPem, caPem);
    }

    @AfterEach
    void stop() throws InterruptedException {
        if (gateway != null) {
            gateway.close();
        }
        executor.shutdownNow();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    @Test
    @Timeout(20)
    void liveSessionRejectsSecondClient() throws Exception {
        gateway = start();
        try (SSLSocket first = connect(port)) {
            ackNotifies(first);
            notifyWhenReady("held");
            AtomicReference<AssertionError> adopted = new AtomicReference<>();
            Thread spare = new Thread(() -> {
                try (SSLSocket ignored = connect(port)) {
                    adopted.set(new AssertionError("second client was adopted"));
                } catch (IOException expected) {
                    /* closed before the handshake while the first session is live */
                }
            });
            spare.start();
            spare.join(5_000);
            assertFalse(spare.isAlive());
            assertNull(adopted.get());
            notifyWhenReady("still-held");
        }
    }

    @Test
    @Timeout(20)
    void closedSessionIsReplaced() throws Exception {
        gateway = start();
        SSLSocket first = connect(port);
        Thread ack = ackNotifies(first);
        notifyWhenReady("before-restart");
        first.close();
        ack.join(2_000);

        try (SSLSocket second = connect(port)) {
            ackNotifies(second);
            notifyWhenReady("after-restart");
        }
    }

    private void notifyWhenReady(String message) throws Exception {
        long deadline = System.nanoTime() + 2_000_000_000L;
        IllegalStateException last = null;
        while (System.nanoTime() < deadline) {
            try {
                gateway.showMessage(message);
                return;
            } catch (IllegalStateException e) {
                last = e;
                Thread.sleep(20);
            }
        }
        throw last;
    }

    private TerminalGateway start() throws IOException {
        port = freePort();
        TerminalGateway started = new TerminalGateway(port);
        started.start(ctx, executor);
        return started;
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static SSLSocket connect(int port) throws IOException {
        return SoftwareTls.createClientSocket(
                "127.0.0.1", port, ctx, SoftwareTls.TlsProfile.PURE_PQC);
    }

    private static Thread ackNotifies(SSLSocket socket) {
        Thread thread = new Thread(() -> {
            try {
                BufferedReader in = TerminalWireProtocol.reader(socket.getInputStream());
                OutputStream out = socket.getOutputStream();
                while (!Thread.currentThread().isInterrupted()) {
                    TerminalWireProtocol.Request request = TerminalWireProtocol.readRequest(in);
                    if (request.type() == TerminalWireProtocol.Type.NOTIFY) {
                        TerminalWireProtocol.writeResponse(out, TerminalWireProtocol.Response.notifyAck());
                    }
                }
            } catch (IOException ignored) {
                /* session replaced or test finished */
            }
        }, "terminal-ack");
        thread.setDaemon(true);
        thread.start();
        return thread;
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
}
