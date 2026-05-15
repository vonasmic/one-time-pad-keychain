package fel.cvut.certGen;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

public class CertGenerator {
    private static final String ML_DSA_ALG = "ML-DSA-44";
    private static final String CERTS_DIR = "certs";
    private static final String CA_PEM = CERTS_DIR + "/root-ca.pem";

    static { Security.addProvider(new BouncyCastleProvider()); }

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("=== FEL CVUT PQC PKI TOOL (2026) ===");

        KeyPair caKeys;
        X509Certificate caCert;
        File caFile = new File(CERTS_DIR + "/root-ca.p12");

        if (caFile.exists()) {
            System.out.println("[!] Existing Root CA found. Loading...");
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            try (FileInputStream fis = new FileInputStream(caFile)) {
                ks.load(fis, "password".toCharArray());
            }
            PrivateKey caPriv = (PrivateKey) ks.getKey("ca", "password".toCharArray());
            caCert = (X509Certificate) ks.getCertificate("ca");
            caKeys = new KeyPair(caCert.getPublicKey(), caPriv);
        } else {
            System.out.println("[*] No CA found. Generating NEW Root CA (ML-DSA)...");
            caKeys = generatePqcKeyPair(ML_DSA_ALG);
            caCert = createRootCA(caKeys);
            save(CERTS_DIR + "/root-ca.p12", "ca", caKeys.getPrivate(), caCert);
            System.out.println("[+] New Root CA saved to root-ca.p12");
        }
        exportCertPem(caCert, CA_PEM);

        System.out.print("\nEnter Node Name (e.g., Alice, Carol): ");
        String name = sc.nextLine().trim();
        if (name.isEmpty()) {
            return;
        }

        System.out.println("-> Generating Pure PQC node (ML-DSA)...");
        KeyPair nodeKeys = generatePqcKeyPair(ML_DSA_ALG);
        X509Certificate nodeCert = issuePurePqc(caCert, caKeys, nodeKeys, name);
        save(CERTS_DIR + "/" + name + ".p12", "node", nodeKeys.getPrivate(), nodeCert);
        System.out.println("[SUCCESS] Created " + name + ".p12 for node " + name);
    }

    private static KeyPair generatePqcKeyPair(String alg) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
        kpg.initialize(new NamedParameterSpec(alg), new SecureRandom());
        return kpg.generateKeyPair();
    }

    private static X509Certificate createRootCA(KeyPair keys) throws Exception {
        X500Name name = new X500Name("CN=PQC-Root-CA, O=CVUT");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + 31536000000L),
                name, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, (ASN1Encodable) new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder(ML_DSA_ALG).setProvider("BC").build(keys.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static X509Certificate issuePurePqc(X509Certificate ca, KeyPair caKeys, KeyPair nodeKeys, String name)
            throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                ca, BigInteger.valueOf(System.currentTimeMillis()), new Date(),
                new Date(System.currentTimeMillis() + 31536000000L),
                new X500Name("CN=" + name), nodeKeys.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(ML_DSA_ALG).setProvider("BC").build(caKeys.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static void exportCertPem(X509Certificate cert, String path) throws Exception {
        File out = new File(path);
        out.getParentFile().mkdirs();
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(b64.getBytes());
            fos.write("\n-----END CERTIFICATE-----\n".getBytes());
        }
    }

    private static void save(String file, String alias, PrivateKey pk, X509Certificate cert) throws Exception {
        new File(file).getParentFile().mkdirs();
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        ks.setKeyEntry(alias, pk, "password".toCharArray(), new java.security.cert.Certificate[]{cert});
        try (FileOutputStream fos = new FileOutputStream(file)) {
            ks.store(fos, "password".toCharArray());
        }
    }
}
