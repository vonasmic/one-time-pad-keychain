package fel.cvut.harness;

import fel.cvut.tls.SoftwareTls;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/** Software ML-DSA-44 CA and leaves for PURE_PQC TLS tests (call {@link SoftwareTls#installSoftware()} first). */
public final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(1);

    private final Path dir;
    private final KeyPair caKeys;
    private final X509Certificate ca;
    private final Path caPem;

    public TestPki(Path dir, String caDn) throws Exception {
        this.dir = dir;
        this.caKeys = mlDsa();
        X500Name name = new X500Name(caDn);
        this.ca = sign(new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(SERIAL.getAndIncrement()), new Date(),
                new Date(System.currentTimeMillis() + 86_400_000L), name, caKeys.getPublic()));
        this.caPem = dir.resolve("ca-" + SERIAL.get() + ".pem");
        writePem(caPem, ca);
    }

    /** Leaf identity under this CA. */
    public Leaf leaf(String cn) throws Exception {
        KeyPair keys = mlDsa();
        X509Certificate cert = sign(new JcaX509v3CertificateBuilder(
                ca, BigInteger.valueOf(SERIAL.getAndIncrement()), new Date(),
                new Date(System.currentTimeMillis() + 86_400_000L), new X500Name("CN=" + cn), keys.getPublic()));
        Path certPem = dir.resolve(cn + "-" + SERIAL.get() + "-cert.pem");
        Path keyPem = dir.resolve(cn + "-" + SERIAL.get() + "-key.pem");
        writePem(certPem, cert);
        writePem(keyPem, keys.getPrivate());
        return new Leaf(cert, SoftwareTls.createContextFromPem(certPem, keyPem, caPem));
    }

    public record Leaf(X509Certificate cert, SSLContext context) {
    }

    private X509Certificate sign(JcaX509v3CertificateBuilder builder) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(caKeys.getPrivate().getAlgorithm())
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caKeys.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    private static KeyPair mlDsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44);
        return kpg.generateKeyPair();
    }

    private static void writePem(Path path, Object pemObject) throws IOException {
        try (var writer = new JcaPEMWriter(Files.newBufferedWriter(path))) {
            writer.writeObject(pemObject);
        }
    }
}
