package fel.cvut.tls;

import CryptoServerJCE.CryptoServerProvider;
import fel.cvut.utimaco.Pqmi;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Public TLS API. All identity private keys live in the HSM (CryptoServer or PQMI).
 */
public final class NodeTls {

    private NodeTls() {
    }

    /**
     * TLS cipher configuration per profile. Each constant is the single source of truth for its
     * protocols/named-groups/signature-schemes — to change or add a profile's preferred crypto,
     * edit (or add) the constant below; no branching logic elsewhere needs to change.
     */
    public enum TlsProfile {
        CLASSICAL(new String[]{"TLSv1.3"}, new String[]{"x25519"}, null),
        PURE_PQC(new String[]{"TLSv1.3"}, new String[]{"MLKEM768"}, new String[]{"mldsa44"});

        private final String[] protocols;
        private final String[] namedGroups;
        private final String[] signatureSchemes;

        TlsProfile(String[] protocols, String[] namedGroups, String[] signatureSchemes) {
            this.protocols = protocols;
            this.namedGroups = namedGroups;
            this.signatureSchemes = signatureSchemes;
        }
    }

    public static SSLParameters parameters(TlsProfile profile) {
        Objects.requireNonNull(profile, "profile must not be null");
        SSLParameters params = new SSLParameters();
        params.setProtocols(profile.protocols);
        params.setNamedGroups(profile.namedGroups);
        if (profile.signatureSchemes != null) {
            params.setSignatureSchemes(profile.signatureSchemes);
        }
        return params;
    }

    public static SSLServerSocket createServerSocket(
            int port, SSLContext ctx, TlsProfile profile, boolean needClientAuth
    ) throws IOException {
        Objects.requireNonNull(ctx, "ctx must not be null");
        SSLServerSocket serverSocket = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(port);
        serverSocket.setNeedClientAuth(needClientAuth);
        serverSocket.setSSLParameters(parameters(profile));
        return serverSocket;
    }

    public static SSLSocket createClientSocket(
            String host, int port, SSLContext ctx, TlsProfile profile
    ) throws IOException {
        Objects.requireNonNull(ctx, "ctx must not be null");
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(host, port);
        socket.setSSLParameters(parameters(profile));
        socket.startHandshake();
        return socket;
    }

    /**
     * Registers JCE/JSSE providers and logs into CryptoServer. Idempotent.
     * Called by the TLS context factories; CertGenerator uses the same entry.
     */
    public static void install(Pqmi session) throws Exception {
        TlsProviders.install(session);
    }

    /** Classical QKD: CryptoServer keystore alias + public trust store. */
    public static SSLContext createContextForQkd(
            Pqmi session, String hsmAlias, Path trustStorePath, char[] trustStorePassword
    ) throws Exception {
        install(session);
        TlsProviders.HsmIdentity id = TlsProviders.loadHsmIdentity(hsmAlias);
        return hsmContext(id.key(), id.chain(), TlsStores.loadTrustStore(trustStorePath, trustStorePassword));
    }

    /** Inter-node PQC: PQMI key + PEM leaf/CA. */
    public static SSLContext createContextForNode(Pqmi session, String nodeId) throws Exception {
        install(session);
        session.loadIdentityKey(session.keyRefForNode(nodeId));

        Path certsDir = TlsStores.resolveCertsDir();
        String certName = TlsStores.certNameForNode(nodeId);
        Path leafPem = certsDir.resolve(certName + ".pem");
        Path caPem = certsDir.resolve("root-ca.pem");
        requireFile(leafPem, "Node certificate");
        requireFile(caPem, "Root CA PEM");

        X509Certificate leaf = TlsStores.readPemCerts(leafPem).get(0);
        X509Certificate ca = TlsStores.readPemCerts(caPem).get(0);
        X509Certificate[] chain = {leaf, ca};
        return hsmContext(new TlsProviders.HsmPrivateKey(session), chain, TlsStores.trustStoreFromCert(ca, caPem));
    }

    public static String certNameForNode(String nodeId) {
        return TlsStores.certNameForNode(nodeId);
    }

    /**
     * Returns the installed CryptoServer JCE provider.
     * Requires a prior {@link #install} call.
     */
    public static CryptoServerProvider requireCryptoServer() {
        return TlsProviders.requireCryptoServer();
    }

    private static SSLContext hsmContext(PrivateKey key, X509Certificate[] chain, KeyStore trust)
            throws Exception {
        KeyManager[] kms = {new TlsProviders.HsmKeyManager(key, chain)};
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        tmf.init(trust);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
        ctx.init(kms, tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
        return ctx;
    }

    private static void requireFile(Path path, String label) {
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException(label + " not found: " + path + " — run CertGenerator first.");
        }
    }
}
