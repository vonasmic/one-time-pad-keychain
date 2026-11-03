package fel.cvut.userapp;

import fel.cvut.tls.SoftwareTls;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * UserApp owner TLS identity.
 */
final class OwnerTls {

    private OwnerTls() {
    }

    static SSLContext load(Path p12, char[] p12Password, Path certPem, Path keyPem, Path caPem)
            throws Exception {
        if (Files.isRegularFile(p12)) {
            return fromPkcs12(p12, p12Password, caPem);
        }
        return SoftwareTls.createContextFromPem(certPem, keyPem, caPem);
    }

    static X509Certificate leaf(Path p12, char[] p12Password, Path certPem) throws Exception {
        if (Files.isRegularFile(p12)) {
            return pkcs12Leaf(p12, p12Password);
        }
        return PeerCertHash.loadCert(certPem);
    }

    private static SSLContext fromPkcs12(Path p12, char[] password, Path caPem) throws Exception {
        SoftwareTls.installSoftware();
        if (!Files.isRegularFile(p12)) {
            throw new IllegalStateException("Owner PKCS#12 not found: " + p12);
        }
        X509Certificate ca = PeerCertHash.loadCert(caPem);
        KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        try (var in = Files.newInputStream(p12)) {
            ks.load(in, password);
        }
        KeyStore trust = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        trust.load(null, null);
        trust.setCertificateEntry("ca", ca);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                "PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        kmf.init(ks, password);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                "PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        tmf.init(trust);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
        return ctx;
    }

    private static X509Certificate pkcs12Leaf(Path p12, char[] password) throws Exception {
        SoftwareTls.installSoftware();
        KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        try (var in = Files.newInputStream(p12)) {
            ks.load(in, password);
        }
        var aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                Certificate cert = ks.getCertificate(alias);
                if (cert instanceof X509Certificate x509) {
                    return x509;
                }
            }
        }
        throw new IOException("no X.509 key entry in " + p12);
    }
}
