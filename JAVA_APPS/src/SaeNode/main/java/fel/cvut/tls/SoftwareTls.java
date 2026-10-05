package fel.cvut.tls;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

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
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Software TLS: PEM / PKCS#12 identity, socket helpers, and USB wrapServer.
 * No CryptoServer / PQMI.
 */
public final class SoftwareTls {

    private static final Object INSTALL_LOCK = new Object();
    private static volatile boolean providersReady;

    private SoftwareTls() {
    }

    /**
     * TLS cipher configuration per profile. Arrays are preference order.
     */
    public enum TlsProfile {
        CLASSICAL(
                new String[]{"TLSv1.3", "TLSv1.2"},
                new String[]{"MLKEM768", "x25519"},
                new String[]{
                        "mldsa44",
                        "ed25519",
                        "ecdsa_secp256r1_sha256",
                        "ecdsa_secp384r1_sha384",
                        "ecdsa_secp521r1_sha512",
                        "rsa_pss_pss_sha256",
                        "rsa_pss_pss_sha384",
                        "rsa_pss_pss_sha512",
                        "rsa_pss_rsae_sha256",
                        "rsa_pss_rsae_sha384",
                        "rsa_pss_rsae_sha512",
                        "rsa_pkcs1_sha256",
                        "rsa_pkcs1_sha384",
                        "rsa_pkcs1_sha512"
                }),
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

    /** BC JSSE + BC only. Used by UserApplication (no HSM). No-op after HSM install. */
    public static void installSoftware() {
        synchronized (INSTALL_LOCK) {
            if (providersReady) {
                return;
            }
            Provider bc = new BouncyCastleProvider();
            JcaTlsCryptoProvider crypto = new JcaTlsCryptoProvider().setProvider(bc);
            List<Provider> providers = List.of(new BouncyCastleJsseProvider(false, crypto), bc);
            for (Provider provider : providers) {
                Security.removeProvider(provider.getName());
            }
            for (int i = providers.size() - 1; i >= 0; i--) {
                Security.insertProviderAt(providers.get(i), 1);
            }
            providersReady = true;
        }
    }

    /** HSM bootstrap already registered JSSE; skip a second software-only insert. */
    public static void markProvidersInstalled() {
        providersReady = true;
    }

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
            return softwareContext(ks, password, caPem);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public static SSLContext createContextFromPkcs12(Path p12, char[] password, Path caPem) throws Exception {
        installSoftware();
        requireFile(p12, "PKCS#12");
        requireFile(caPem, "CA PEM");
        return softwareContext(TlsStores.loadPkcs12(p12, password), password, caPem);
    }

    public static PrivateKey softwarePrivateKey(Path keyPem) throws Exception {
        installSoftware();
        requireFile(keyPem, "Private key");
        return TlsStores.readPemPrivateKey(keyPem);
    }

    public static X509Certificate softwareLeafFromPem(Path certPem) throws Exception {
        installSoftware();
        requireFile(certPem, "Leaf certificate");
        return TlsStores.readPemCerts(certPem).get(0);
    }

    public static X509Certificate softwareLeafFromPkcs12(Path p12, char[] password) throws Exception {
        installSoftware();
        requireFile(p12, "PKCS#12");
        return TlsStores.leafFromPkcs12(TlsStores.loadPkcs12(p12, password), p12);
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

    static SSLContext softwareContext(KeyStore identity, char[] password, Path caPem)
            throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                "PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        kmf.init(identity, password);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                "PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        tmf.init(TlsStores.trustStoreFromCert(TlsStores.readPemCerts(caPem).get(0), caPem));
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
        return ctx;
    }

    public static void requireFile(Path path, String label) {
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException(label + " not found: " + path + " — run CertGenerator first.");
        }
    }
}
