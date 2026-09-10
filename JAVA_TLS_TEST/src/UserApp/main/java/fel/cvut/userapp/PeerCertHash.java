package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Peer hash for {@code PEER ADD}: SHA384 of raw subjectPublicKey bits (BIT STRING
 * payload, no unused-bits byte), matching firmware.
 * Not {@code PublicKey.getEncoded()} (full SPKI DER).
 */
public final class PeerCertHash {

    public static final Pattern NICKNAME = Pattern.compile("[A-Za-z0-9_.-]{1,16}");
    public static final Pattern HASH_HEX = Pattern.compile("[0-9a-fA-F]{96}");

    private PeerCertHash() {
    }

    public static X509Certificate loadCert(Path path) throws Exception {
        Objects.requireNonNull(path, "path");
        ensureBc();
        if (!Files.isRegularFile(path)) {
            throw new IOException("Certificate not found: " + path);
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        try (InputStream in = new BufferedInputStream(Files.newInputStream(path))) {
            for (Certificate certificate : cf.generateCertificates(in)) {
                if (certificate instanceof X509Certificate x509) {
                    return x509;
                }
            }
        }
        throw new IOException("No X.509 certificate in: " + path);
    }

    /**
     * Raw subjectPublicKey bits (BIT STRING payload). Same bytes firmware hashes
     * for {@code PEER ADD}.
     */
    public static byte[] rawSpkiBits(X509Certificate cert) throws IOException {
        Objects.requireNonNull(cert, "cert");
        try {
            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            ASN1BitString bits = holder.getSubjectPublicKeyInfo().getPublicKeyData();
            if (bits == null) {
                throw new IOException("Certificate has no subjectPublicKey");
            }
            byte[] raw = bits.getBytes();
            if (raw == null || raw.length == 0) {
                throw new IOException("Empty subjectPublicKey bits");
            }
            return raw;
        } catch (CertificateEncodingException e) {
            throw new IOException("Could not encode certificate", e);
        }
    }

    public static String hashHex(X509Certificate cert) throws IOException {
        return SeBytes.toHex(SeBytes.sha384(rawSpkiBits(cert)));
    }

    public static String hashHex(Path path) throws Exception {
        return hashHex(loadCert(path));
    }

    /** Validates and normalizes a 96-digit SHA384 peer hash for {@code PEER ADD}. */
    public static String parseHashHex(String hashHex) {
        Objects.requireNonNull(hashHex, "hashHex");
        String trimmed = hashHex.strip();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("peer hash must not be empty");
        }
        if (!HASH_HEX.matcher(trimmed).matches()) {
            throw new IllegalArgumentException("peer hash must be exactly 96 hex digits (SHA384)");
        }
        return trimmed.toLowerCase(Locale.ROOT);
    }

    public static boolean validNickname(String name) {
        return name != null && NICKNAME.matcher(name).matches();
    }

    private static void ensureBc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
