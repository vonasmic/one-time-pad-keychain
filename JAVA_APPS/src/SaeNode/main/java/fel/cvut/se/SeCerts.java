package fel.cvut.se;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.cert.X509CertificateHolder;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Raw {@code subjectPublicKey} bits (BIT STRING payload), not SPKI DER.
 */
public final class SeCerts {

    private SeCerts() {
    }

    public static byte[] rawSubjectPublicKeyBits(X509Certificate cert) throws IOException {
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
}
