package fel.cvut.tls;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;

/**
 * Software-only client-CA leaf issue (INIT LAB). No HSM / CertGenerator.
 */
public final class SoftwareLeaf {

    public static final String DEVICE_CLIENT_CN = "native-tls-client";
    public static final String DEVICE_CLIENT_CN_2 = "native-tls-client-2";

    private static final MLDSAParameterSpec ML_DSA_PARAM = MLDSAParameterSpec.ml_dsa_44;

    private SoftwareLeaf() {
    }

    /**
     * Sign a raw ML-DSA-44 public key with the lab client CA PKCS#12 ({@code alias ca}).
     */
    public static X509Certificate signRawMlDsa44Leaf(Path caP12, String password, byte[] rawPub, String cn)
            throws Exception {
        Objects.requireNonNull(caP12, "caP12");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(rawPub, "rawPub");
        Objects.requireNonNull(cn, "cn");
        if (rawPub.length != 1312) {
            throw new IllegalArgumentException("ML-DSA-44 public key must be 1312 bytes");
        }
        SoftwareTls.installSoftware();
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        try (FileInputStream fis = new FileInputStream(caP12.toFile())) {
            ks.load(fis, password.toCharArray());
        }
        PrivateKey caPriv = (PrivateKey) ks.getKey("ca", password.toCharArray());
        X509Certificate caCert = (X509Certificate) ks.getCertificate("ca");
        if (caPriv == null || caCert == null) {
            throw new IllegalStateException("PKCS#12 " + caP12 + " has no alias 'ca'");
        }
        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "BC");
        PublicKey pub = kf.generatePublic(new MLDSAPublicKeySpec(ML_DSA_PARAM, rawPub));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caCert, BigInteger.valueOf(System.currentTimeMillis()), new Date(),
                new Date(System.currentTimeMillis() + 31536000000L),
                new X500Name("CN=" + cn), pub);
        ContentSigner signer = new JcaContentSignerBuilder(caPriv.getAlgorithm())
                .setProvider("BC")
                .build(caPriv);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    public static void writeCertPem(X509Certificate cert, Path path) throws Exception {
        Objects.requireNonNull(cert, "cert");
        Objects.requireNonNull(path, "path");
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        try (FileOutputStream fos = new FileOutputStream(path.toFile())) {
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(b64.getBytes());
            fos.write("\n-----END CERTIFICATE-----\n".getBytes());
        }
    }
}
