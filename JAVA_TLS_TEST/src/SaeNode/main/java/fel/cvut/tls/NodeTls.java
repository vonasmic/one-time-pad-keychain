package fel.cvut.tls;

import CryptoServerJCE.CryptoServerProvider;
import fel.cvut.se.SeSessionBinding;
import fel.cvut.utimaco.Pqmi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;

/**
 * Public TLS API. SAE node identity keys live in the HSM (CryptoServer or PQMI).
 * {@link #createContextFromPem} is the software-PEM path used by UserApplication.
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
        return createServerSocket(port, ctx, profile, needClientAuth, null);
    }

    public static SSLServerSocket createServerSocket(
            int port, SSLContext ctx, TlsProfile profile, boolean needClientAuth, InetAddress bindAddress
    ) throws IOException {
        Objects.requireNonNull(ctx, "ctx must not be null");
        SSLServerSocket serverSocket = bindAddress == null
                ? (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(port)
                : (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(port, 0, bindAddress);
        /* setSSLParameters resets client auth, so carry it in the parameters. */
        SSLParameters params = parameters(profile);
        params.setNeedClientAuth(needClientAuth);
        serverSocket.setSSLParameters(params);
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
     * TLS server handshake over an already-connected transport (USB CDC after
     * {@code ENCRYPT}/{@code DECRYPT} arming). The device is the TLS client.
     */
    public static SSLSocket wrapServer(SSLContext ctx, Socket transport) throws IOException {
        return wrapServer(ctx, transport, TlsProfile.PURE_PQC, true);
    }

    public static SSLSocket wrapServer(
            SSLContext ctx, Socket transport, TlsProfile profile, boolean needClientAuth
    ) throws IOException {
        Objects.requireNonNull(ctx, "ctx must not be null");
        Objects.requireNonNull(transport, "transport must not be null");
        SSLSocket ssl = (SSLSocket) ctx.getSocketFactory().createSocket(transport, "localhost", 0, true);
        ssl.setUseClientMode(false);
        ssl.setNeedClientAuth(needClientAuth);
        SSLParameters params = parameters(profile);
        params.setNeedClientAuth(needClientAuth);
        ssl.setSSLParameters(params);
        return ssl;
    }

    /**
     * Registers JCE/JSSE providers and logs into CryptoServer. Idempotent.
     * Called by the TLS context factories; CertGenerator uses the same entry.
     */
    public static void install(Pqmi session) throws Exception {
        TlsProviders.install(session);
    }

    /** BC JSSE + BC only. Used by UserApplication (no HSM). */
    public static void installSoftware() {
        TlsProviders.installSoftware();
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

        Path leafPem = TlsStores.nodeLeafPem(nodeId);
        Path caPem = TlsStores.rootCaPem();
        requireFile(leafPem, "Node certificate");
        requireFile(caPem, "Root CA PEM");

        X509Certificate leaf = TlsStores.readPemCerts(leafPem).get(0);
        X509Certificate ca = TlsStores.readPemCerts(caPem).get(0);
        X509Certificate[] chain = {leaf, ca};
        return hsmContext(new TlsProviders.HsmPrivateKey(session), chain, TlsStores.trustStoreFromCert(ca, caPem));
    }

    /**
     * Command-server mTLS: same HSM node identity as {@link #createContextForNode}, but client
     * authentication trusts {@code ca/client_ca.pem} (device and user certs).
     */
    public static SSLContext createContextForCommandServer(Pqmi session, String nodeId) throws Exception {
        install(session);
        session.loadIdentityKey(session.keyRefForNode(nodeId));

        Path leafPem = TlsStores.nodeLeafPem(nodeId);
        Path saeCaPem = TlsStores.rootCaPem();
        Path clientCaPem = TlsStores.clientCaPem();
        requireFile(leafPem, "Node certificate");
        requireFile(saeCaPem, "Root CA PEM");
        requireFile(clientCaPem, "Client CA PEM");

        X509Certificate leaf = TlsStores.readPemCerts(leafPem).get(0);
        X509Certificate saeCa = TlsStores.readPemCerts(saeCaPem).get(0);
        X509Certificate clientCa = TlsStores.readPemCerts(clientCaPem).get(0);
        X509Certificate[] chain = {leaf, saeCa};
        return hsmContext(
                new TlsProviders.HsmPrivateKey(session),
                chain,
                TlsStores.trustStoreFromCert(clientCa, clientCaPem));
    }

    /**
     * Software ML-DSA identity from PEM files (UserApplication). Private key is loaded into an
     * in-memory PKCS#12 store; BC JSSE signs in process. No HSM / PQMI.
     */
    public static SSLContext createContextFromPem(Path leafPem, Path keyPem, Path caPem) throws Exception {
        installSoftware();
        requireFile(leafPem, "Leaf certificate");
        requireFile(keyPem, "Private key");
        requireFile(caPem, "CA PEM");

        X509Certificate leaf = TlsStores.readPemCerts(leafPem).get(0);
        X509Certificate ca = TlsStores.readPemCerts(caPem).get(0);
        PrivateKey key = TlsStores.readPemPrivateKey(keyPem);

        char[] password = "software".toCharArray();
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            ks.load(null, null);
            ks.setKeyEntry("user", key, password, new Certificate[]{leaf, ca});

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    "PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            kmf.init(ks, password);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    "PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            tmf.init(TlsStores.trustStoreFromCert(ca, caPem));

            SSLContext ctx = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
            return ctx;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /** Software ML-DSA private key from PEM (UserApp owner signing). */
    public static PrivateKey softwarePrivateKey(Path keyPem) throws Exception {
        installSoftware();
        requireFile(keyPem, "Private key");
        return TlsStores.readPemPrivateKey(keyPem);
    }

    public static String certNameForNode(String nodeId) {
        return TlsStores.certNameForNode(nodeId);
    }

    public static Path certsDir() {
        return TlsStores.resolveCertsDir();
    }

    public static Path clientCaPem() {
        return TlsStores.clientCaPem();
    }

    public static Path rootCaPem() {
        return TlsStores.rootCaPem();
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
        ctx.init(kms, SeSessionBinding.wrapTrustManagers(tmf.getTrustManagers()), SecureRandom.getInstanceStrong());
        return ctx;
    }

    private static void requireFile(Path path, String label) {
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException(label + " not found: " + path + " — run CertGenerator first.");
        }
    }
}
