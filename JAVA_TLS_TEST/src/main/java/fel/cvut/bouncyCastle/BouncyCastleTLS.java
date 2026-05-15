package fel.cvut.bouncyCastle;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;

public class BouncyCastleTLS {

    private static final String[] TLS_1_3_ONLY = {"TLSv1.3"};

    /** TLS 1.3 signature schemes for ML-DSA (FIPS 204). */
    private static final String[] ML_DSA_SIGNATURE_SCHEMES = {
            "mldsa44",
            "mldsa65",
            "mldsa87",
    };

    /** Hybrid classical + ML-KEM key exchange groups. */
    private static final String[] HYBRID_NAMED_GROUPS = {
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
    };

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

    public static SSLParameters createPqcTlsParameters() {
        SSLParameters params = new SSLParameters();
        params.setProtocols(TLS_1_3_ONLY);
        params.setSignatureSchemes(ML_DSA_SIGNATURE_SCHEMES);
        params.setNamedGroups(HYBRID_NAMED_GROUPS);
        return params;
    }

    public static void applyPqcTlsParameters(SSLParameters params) {
        params.setProtocols(TLS_1_3_ONLY);
        params.setSignatureSchemes(ML_DSA_SIGNATURE_SCHEMES);
        params.setNamedGroups(HYBRID_NAMED_GROUPS);
    }
}
