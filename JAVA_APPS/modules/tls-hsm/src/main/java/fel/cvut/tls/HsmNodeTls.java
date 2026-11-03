package fel.cvut.tls;

import CryptoServerJCE.CryptoServerProvider;
import fel.cvut.se.SeSessionBinding;
import fel.cvut.utimaco.Pqmi;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * SAE HSM TLS factories (CryptoServer / PQMI). UserApp uses {@link SoftwareTls}.
 */
public final class HsmNodeTls {

    private HsmNodeTls() {
    }

    public static void install(Pqmi session) throws Exception {
        TlsProviders.install(session);
    }

    public static SSLContext createContextForQkd(
            Pqmi session, String hsmAlias, Path trustStorePath, char[] trustStorePassword
    ) throws Exception {
        install(session);
        TlsProviders.HsmIdentity id = TlsProviders.loadHsmIdentity(hsmAlias);
        return hsmContext(id.key(), id.chain(), TlsStores.loadTrustStore(trustStorePath, trustStorePassword));
    }

    public static SSLContext createContextForNode(Pqmi session, String nodeId) throws Exception {
        install(session);
        session.loadIdentityKey(session.keyRefForNode(nodeId));

        Path leafPem = TlsStores.nodeLeafPem(nodeId);
        Path caPem = TlsStores.rootCaPem();
        SoftwareTls.requireFile(leafPem, "Node certificate");
        SoftwareTls.requireFile(caPem, "Root CA PEM");

        X509Certificate leaf = TlsStores.readPemCerts(leafPem).get(0);
        X509Certificate ca = TlsStores.readPemCerts(caPem).get(0);
        X509Certificate[] chain = {leaf, ca};
        return hsmContext(new TlsProviders.HsmPrivateKey(session), chain, TlsStores.trustStoreFromCert(ca, caPem));
    }

    public static SSLContext createContextForCommandServer(Pqmi session, String nodeId) throws Exception {
        install(session);
        session.loadIdentityKey(session.keyRefForNode(nodeId));

        Path leafPem = TlsStores.nodeLeafPem(nodeId);
        Path saeCaPem = TlsStores.rootCaPem();
        Path clientCaPem = TlsStores.clientCaPem();
        SoftwareTls.requireFile(leafPem, "Node certificate");
        SoftwareTls.requireFile(saeCaPem, "Root CA PEM");
        SoftwareTls.requireFile(clientCaPem, "Client CA PEM");

        X509Certificate leaf = TlsStores.readPemCerts(leafPem).get(0);
        X509Certificate saeCa = TlsStores.readPemCerts(saeCaPem).get(0);
        X509Certificate clientCa = TlsStores.readPemCerts(clientCaPem).get(0);
        X509Certificate[] chain = {leaf, saeCa};
        return hsmContext(
                new TlsProviders.HsmPrivateKey(session),
                chain,
                TlsStores.trustStoreFromCert(clientCa, clientCaPem));
    }

    public static CryptoServerProvider requireCryptoServer() {
        return TlsProviders.requireCryptoServer();
    }

    private static SSLContext hsmContext(PrivateKey key, X509Certificate[] chain, java.security.KeyStore trust)
            throws Exception {
        Objects.requireNonNull(key, "key");
        KeyManager[] kms = {new TlsProviders.HsmKeyManager(key, chain)};
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        tmf.init(trust);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
        ctx.init(kms, SeSessionBinding.wrapTrustManagers(tmf.getTrustManagers()), SecureRandom.getInstanceStrong());
        return ctx;
    }
}
