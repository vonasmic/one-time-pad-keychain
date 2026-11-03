package fel.cvut.tls;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** PKCS#12 / PEM trust and leaf certificate loading. */
public final class TlsStores {

    static final String CERTS_DIR_PROPERTY = "pqc.certs.dir";
    static final String DEFAULT_CERTS_DIR = "certs";
    static final String CA_SUBDIR = "ca";
    static final String DEFAULT_ROOT_CA = "root-ca";
    static final String DEFAULT_CLIENT_CA = "client_ca";

    private TlsStores() {
    }

    public static Path resolveCertsDir() {
        String fromProperty = System.getProperty(CERTS_DIR_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return Path.of(fromProperty.trim());
        }
        String fromEnv = System.getenv("PQC_CERTS_DIR");
        if (fromEnv != null && !fromEnv.isBlank()) {
            return Path.of(fromEnv.trim());
        }
        return Path.of(DEFAULT_CERTS_DIR);
    }

    public static Path caDir() {
        return resolveCertsDir().resolve(CA_SUBDIR);
    }

    public static Path rootCaPem() {
        return caPem(caBaseName("CERTGEN_ROOT_CA", DEFAULT_ROOT_CA));
    }

    public static Path clientCaPem() {
        return caPem(caBaseName("CERTGEN_CLIENT_CA", DEFAULT_CLIENT_CA));
    }

    public static Path nodeLeafPem(String nodeId) {
        return resolveCertsDir().resolve(certNameForNode(nodeId) + ".pem");
    }

    private static Path caPem(String baseName) {
        return caDir().resolve(baseName + ".pem");
    }

    private static String caBaseName(String envName, String defaultName) {
        String value = System.getenv(envName);
        if (value == null || value.isBlank()) {
            return defaultName;
        }
        String name = value.trim();
        if (name.endsWith(".pem") || name.endsWith(".p12")) {
            name = name.substring(0, name.lastIndexOf('.')).trim();
        }
        return name;
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
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        try (var in = Files.newInputStream(keyStorePath)) {
            keyStore.load(in, keyStorePassword);
        } catch (IOException e) {
            throw new IOException("Failed to load PKCS12 store: " + keyStorePath, e);
        }
        return keyStore;
    }

    /** First X.509 certificate attached to a key entry in a PKCS#12 identity store. */
    public static X509Certificate leafFromPkcs12(KeyStore keyStore, Path source) throws Exception {
        var aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate x509) {
                    return x509;
                }
            }
        }
        throw new IOException("no X.509 key entry in " + source);
    }

    /**
     * Loads a trust store from PKCS#12 or PEM (.pem / .crt).
     * OpenSSL {@code pkcs12 -export -nokeys} often produces PKCS#12 files that Java cannot read (0 entries);
     * use {@code keytool -importcert} for PKCS#12 trust stores, or pass the server CA as PEM.
     */
    public static KeyStore loadTrustStore(Path trustStorePath, char[] trustStorePassword) throws Exception {
        String fileName = trustStorePath.getFileName().toString().toLowerCase(Locale.ROOT);
        if (fileName.endsWith(".pem") || fileName.endsWith(".crt")) {
            return trustStoreFromCerts(readPemCerts(trustStorePath), trustStorePath);
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

    public static KeyStore trustStoreFromCert(X509Certificate cert, Path source) throws Exception {
        return trustStoreFromCerts(List.of(cert), source);
    }

    /** Parses all X.509 certificates from a PEM/DER stream. */
    public static List<X509Certificate> readPemCerts(Path pemPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        List<X509Certificate> out = new ArrayList<>();
        try (InputStream in = new BufferedInputStream(Files.newInputStream(pemPath))) {
            for (Certificate certificate : cf.generateCertificates(in)) {
                if (certificate instanceof X509Certificate x509) {
                    out.add(x509);
                }
            }
        }
        if (out.isEmpty()) {
            throw new IOException("No X.509 certificates found in: " + pemPath);
        }
        return out;
    }

    /** Parses a PKCS#8 or traditional PEM private key. */
    public static PrivateKey readPemPrivateKey(Path pemPath) throws Exception {
        try (var reader = Files.newBufferedReader(pemPath);
             PEMParser parser = new PEMParser(reader)) {
            Object obj = parser.readObject();
            if (obj == null) {
                throw new IOException("No PEM object in: " + pemPath);
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (obj instanceof PrivateKeyInfo info) {
                return converter.getPrivateKey(info);
            }
            if (obj instanceof PEMKeyPair pair) {
                return converter.getPrivateKey(pair.getPrivateKeyInfo());
            }
            throw new IOException("Unsupported PEM key type " + obj.getClass().getName() + " in: " + pemPath);
        }
    }

    private static KeyStore trustStoreFromCerts(List<X509Certificate> certs, Path source) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        trustStore.load(null, null);
        String base = source.getFileName().toString();
        for (int i = 0; i < certs.size(); i++) {
            trustStore.setCertificateEntry(base + "-" + i, certs.get(i));
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
}
