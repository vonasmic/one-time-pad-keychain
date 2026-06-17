package fel.cvut.bouncyCastle;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;

public class BouncyCastleTLS {

    public static final String CERTS_DIR_PROPERTY = "pqc.certs.dir";
    public static final String DEFAULT_CERTS_DIR = "certs";
    public static final String KEYSTORE_PASSWORD_PROPERTY = "pqc.keystore.password";
    public static final String DEFAULT_KEYSTORE_PASSWORD = "password";

    private static final String[] TLS_1_3_ONLY = {"TLSv1.3"};

    /** Pure PQC TLS 1.3 ML-DSA signature schemes (must match CertGenerator key parameter set). */
    private static final String[] PQC_SIGNATURE_SCHEMES = {
            "mldsa44",
    };

    /** Hybrid/composite signature schemes produced by CertGenerator (provider-dependent names). */
    private static final String[] HYBRID_SIGNATURE_SCHEMES = {
            "ecdsa_secp384r1_mldsa65",
    };

    /** Classical fallback signature schemes. */
    private static final String[] CLASSICAL_SIGNATURE_SCHEMES = {
            "ed25519",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha256",
    };

    /**
     * Signature preference for non-strict mode:
     * pure PQC first, then hybrid/composite, then classical fallback.
     */
    private static final String[] PREFERRED_SIGNATURE_SCHEMES = concat(
            PQC_SIGNATURE_SCHEMES,
            HYBRID_SIGNATURE_SCHEMES,
            CLASSICAL_SIGNATURE_SCHEMES
    );

    /** Signature fallback when pure PQC signature names are unsupported. */
    private static final String[] HYBRID_THEN_CLASSICAL_SIGNATURE_SCHEMES = concat(
            HYBRID_SIGNATURE_SCHEMES,
            CLASSICAL_SIGNATURE_SCHEMES
    );

    /** Pure ML-KEM key exchange groups. */
    private static final String[] PURE_PQC_NAMED_GROUPS = {
            "MLKEM768",
    };

    /** Hybrid classical + ML-KEM key exchange groups. */
    private static final String[] HYBRID_NAMED_GROUPS = {
            "X25519MLKEM768",
            "SecP384r1MLKEM1024",
    };

    /**
     * Group preference for non-strict mode:
     * pure PQC first, then hybrid PQC, then classical fallback.
     */
    private static final String[] PREFERRED_NAMED_GROUPS = concat(
            PURE_PQC_NAMED_GROUPS,
            HYBRID_NAMED_GROUPS,
            new String[]{"x25519", "secp384r1"}
    );

    public static void ensureProvidersRegistered() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleJsseProvider());
        }
    }

    public static SSLContext createBouncyCastleContext(KeyStore keyStore, char[] password, KeyStore trustStore)
            throws Exception {
        ensureProvidersRegistered();

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        kmf.init(keyStore, password);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        tmf.init(trustStore);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    public static SSLContext createBouncyCastleContextFromPkcs12(
            Path keyStorePath,
            char[] keyStorePassword,
            Path trustStorePath,
            char[] trustStorePassword
    ) throws Exception {
        ensureProvidersRegistered();
        KeyStore keyStore = loadPkcs12(keyStorePath, keyStorePassword);
        KeyStore trustStore = loadTrustStore(trustStorePath, trustStorePassword);
        return createBouncyCastleContext(keyStore, keyStorePassword, trustStore);
    }

    public static SSLContext loadContextForNode(String nodeId) throws Exception {
        Path certsDir = resolveCertsDir();
        char[] password = resolveKeystorePassword();
        Path pemTrust = certsDir.resolve("root-ca.pem");
        Path trustStorePath = Files.exists(pemTrust) ? pemTrust : certsDir.resolve("root-ca.p12");
        return createBouncyCastleContextFromPkcs12(
                certsDir.resolve(certNameForNode(nodeId) + ".p12"),
                password,
                trustStorePath,
                password
        );
    }

    public static Path resolveCertsDir() {
        return Path.of(System.getProperty(CERTS_DIR_PROPERTY, DEFAULT_CERTS_DIR));
    }

    public static char[] resolveKeystorePassword() {
        return System.getProperty(KEYSTORE_PASSWORD_PROPERTY, DEFAULT_KEYSTORE_PASSWORD).toCharArray();
    }

    public static String certNameForNode(String nodeId) {
        String normalizedNodeId = Objects.requireNonNull(nodeId, "nodeId must not be null")
                .toUpperCase(Locale.ROOT);
        return switch (normalizedNodeId) {
            case "ALICE" -> "Alice";
            case "BOB" -> "Bob";
            case "CAROL" -> "Carol";
            default -> nodeId;
        };
    }

    public static KeyStore loadPkcs12(Path keyStorePath, char[] keyStorePassword) throws Exception {
        ensureProvidersRegistered();
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        try (var in = Files.newInputStream(keyStorePath)) {
            keyStore.load(in, keyStorePassword);
        } catch (IOException e) {
            throw new IOException("Failed to load PKCS12 store: " + keyStorePath, e);
        }
        return keyStore;
    }

    /**
     * Loads a trust store from PKCS#12 or PEM (.pem / .crt).
     * OpenSSL {@code pkcs12 -export -nokeys} often produces PKCS#12 files that Java cannot read (0 entries);
     * use {@code keytool -importcert} for PKCS#12 trust stores, or pass the server CA as PEM.
     */
    public static KeyStore loadTrustStore(Path trustStorePath, char[] trustStorePassword) throws Exception {
        String fileName = trustStorePath.getFileName().toString().toLowerCase(Locale.ROOT);
        if (fileName.endsWith(".pem") || fileName.endsWith(".crt")) {
            return loadTrustStoreFromPem(trustStorePath);
        }

        KeyStore trustStore = loadPkcs12(trustStorePath, trustStorePassword);
        if (countKeyStoreEntries(trustStore) == 0) {
            throw new IOException(
                    "Trust store has no certificate entries: " + trustStorePath + ". "
                            + "OpenSSL cert-only PKCS#12 is not readable by Java. "
                            + "Recreate with keytool -importcert (see certs/qkd/README.md)."
            );
        }
        return trustStore;
    }

    public static KeyStore loadTrustStoreFromPem(Path pemPath) throws Exception {
        ensureProvidersRegistered();
        KeyStore trustStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        trustStore.load(null, null);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        try (InputStream in = new BufferedInputStream(Files.newInputStream(pemPath))) {
            int index = 0;
            for (Certificate certificate : certificateFactory.generateCertificates(in)) {
                if (!(certificate instanceof X509Certificate x509Certificate)) {
                    continue;
                }
                String alias = pemPath.getFileName().toString() + "-" + index++;
                trustStore.setCertificateEntry(alias, x509Certificate);
            }
        }

        if (countKeyStoreEntries(trustStore) == 0) {
            throw new IOException("No X.509 certificates found in PEM trust store: " + pemPath);
        }
        return trustStore;
    }

    private static int countKeyStoreEntries(KeyStore keyStore) throws Exception {
        int count = 0;
        var aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            aliases.nextElement();
            count++;
        }
        return count;
    }

    public static String[] protocolsFor(TlsPolicy tlsPolicy) {
        TlsPolicy effectivePolicy = tlsPolicy == null ? TlsPolicy.defaultPolicy() : tlsPolicy;
        if (effectivePolicy.preferTls13()) {
            if (effectivePolicy.allowTls12()) {
                return new String[]{"TLSv1.3", "TLSv1.2"};
            }
            return TLS_1_3_ONLY.clone();
        }
        if (effectivePolicy.allowTls12()) {
            return new String[]{"TLSv1.2"};
        }
        // Keep at least one protocol so callers never end up with an empty list.
        return TLS_1_3_ONLY.clone();
    }

    public static SSLParameters createTlsParameters(TlsPolicy tlsPolicy) {
        TlsPolicy effectivePolicy = tlsPolicy == null ? TlsPolicy.defaultPolicy() : tlsPolicy;
        SSLParameters params = new SSLParameters();
        applyTlsPolicy(params, effectivePolicy);
        return params;
    }

    public static void applyTlsPolicy(SSLParameters params, TlsPolicy tlsPolicy) {
        Objects.requireNonNull(params, "params must not be null");
        TlsPolicy effectivePolicy = tlsPolicy == null ? TlsPolicy.defaultPolicy() : tlsPolicy;
        params.setProtocols(protocolsFor(effectivePolicy));
        if (effectivePolicy.purePqcRequired()) {
            if (!trySetSignatureSchemes(params, PQC_SIGNATURE_SCHEMES)) {
                throw new IllegalStateException("purePQC policy requested, but ML-DSA signature schemes are unsupported.");
            }
            try {
                params.setNamedGroups(HYBRID_NAMED_GROUPS);
            } catch (RuntimeException e) {
                throw new IllegalStateException("purePQC policy requested, but hybrid KEM named groups are unsupported.", e);
            }
            return;
        }

        if (!trySetSignatureSchemes(params, PREFERRED_SIGNATURE_SCHEMES)
                && !trySetSignatureSchemes(params, HYBRID_THEN_CLASSICAL_SIGNATURE_SCHEMES)) {
            trySetSignatureSchemes(params, CLASSICAL_SIGNATURE_SCHEMES);
        }
        if (!trySetNamedGroups(params, PREFERRED_NAMED_GROUPS)
                && !trySetNamedGroups(params, concat(PURE_PQC_NAMED_GROUPS, HYBRID_NAMED_GROUPS))) {
            trySetNamedGroups(params, new String[]{"x25519", "secp384r1"});
        }
    }

    private static boolean trySetSignatureSchemes(SSLParameters params, String[] signatureSchemes) {
        try {
            params.setSignatureSchemes(signatureSchemes);
            return true;
        } catch (RuntimeException ignored) {
            // Some providers reject unknown/non-enabled names.
            return false;
        }
    }

    private static boolean trySetNamedGroups(SSLParameters params, String[] namedGroups) {
        try {
            params.setNamedGroups(namedGroups);
            return true;
        } catch (RuntimeException ignored) {
            // Some providers reject unknown/non-enabled names.
            return false;
        }
    }

    private static String[] concat(String[]... arrays) {
        int totalLength = 0;
        for (String[] array : arrays) {
            totalLength += array.length;
        }
        String[] result = new String[totalLength];
        int offset = 0;
        for (String[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    public static SSLParameters createPqcTlsParameters() {
        return createTlsParameters(TlsPolicy.purePqc());
    }

    public static void applyPqcTlsParameters(SSLParameters params) {
        applyTlsPolicy(params, TlsPolicy.purePqc());
    }

    public static String[] tls13OnlyProtocols() {
        return protocolsFor(TlsPolicy.purePqc());
    }

    public record TlsPolicy(boolean preferTls13, boolean allowTls12, boolean purePqcRequired, Duration connectTimeout) {
        public TlsPolicy {
            connectTimeout = connectTimeout == null ? Duration.ofSeconds(10) : connectTimeout;
        }

        public static TlsPolicy defaultPolicy() {
            return new TlsPolicy(true, true, false, Duration.ofSeconds(10));
        }

        /** ML-DSA signatures only, hybrid KEM groups only, TLS 1.3 only. */
        public static TlsPolicy purePqc() {
            return new TlsPolicy(true, false, true, Duration.ofSeconds(10));
        }
    }
}
