package fel.cvut.tls;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** PKCS#12 / PEM trust and leaf certificate loading. */
final class TlsStores {

    static final String CERTS_DIR_PROPERTY = "pqc.certs.dir";
    static final String DEFAULT_CERTS_DIR = "certs";

    private TlsStores() {
    }

    static Path resolveCertsDir() {
        return Path.of(System.getProperty(CERTS_DIR_PROPERTY, DEFAULT_CERTS_DIR));
    }

    static String certNameForNode(String nodeId) {
        String normalizedNodeId = Objects.requireNonNull(nodeId, "nodeId must not be null")
                .toUpperCase(Locale.ROOT);
        return switch (normalizedNodeId) {
            case "ALICE" -> "Alice";
            case "BOB" -> "Bob";
            case "CAROL" -> "Carol";
            default -> nodeId;
        };
    }

    static KeyStore loadPkcs12(Path keyStorePath, char[] keyStorePassword) throws Exception {
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
    static KeyStore loadTrustStore(Path trustStorePath, char[] trustStorePassword) throws Exception {
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

    static KeyStore trustStoreFromCert(X509Certificate cert, Path source) throws Exception {
        return trustStoreFromCerts(List.of(cert), source);
    }

    /** Parses all X.509 certificates from a PEM/DER stream. */
    static List<X509Certificate> readPemCerts(Path pemPath) throws Exception {
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
