package fel.cvut.certGen;

import fel.cvut.se.EnvSecrets;
import fel.cvut.tls.HsmNodeTls;
import fel.cvut.tls.SoftwareLeaf;
import fel.cvut.tls.SoftwareTls;
import fel.cvut.utimaco.HsmGate;
import fel.cvut.utimaco.Pqmi;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Non-interactive PKI / HSM provisioning driven by {@code env/certgen.env}:
 * <ul>
 *   <li>Root CA and client CA (load existing PKCS#12, or create if missing)</li>
 *   <li>Node leaves: generate missing PQMI ML-DSA keys, issue missing PEMs</li>
 *   <li>QuKayDee SAE PKCS#12 files under {@code certs/qkd/}: import missing aliases into CryptoServer</li>
 * </ul>
 * Device and user client keys/certs are provisioned by UserApp (or an external CA), not here.
 * If the HSM is unreachable, software CAs are still created; node keys and QuKayDee import are skipped.
 */
public class CertGenerator {
    private static final MLDSAParameterSpec ML_DSA_PARAM = MLDSAParameterSpec.ml_dsa_44;
    private static final String WARN = "\u001B[38;5;208m";
    private static final String RESET = "\u001B[0m";
    private static final String CERTS_DIR = "certs";
    private static final String CA_DIR = "ca";
    private static final String QKD_DIR = "certs/qkd";
    private static final Pattern QKD_CLIENT_P12 = Pattern.compile("(.+)-client\\.p12$");
    /** Set once in {@link #main}; protects CA / QuKayDee PKCS#12 material. */
    private static char[] pkcs12Password;

    public static void main(String[] args) throws Exception {
        Map<String, String> fileValues = CertGenConfig.loadFileValues();
        pkcs12Password = EnvSecrets.envOrScan(fileValues, "PKCS12_PASSWORD").toCharArray();
        CertGenConfig config = CertGenConfig.from(fileValues);
        Pqmi pqmi = null;
        boolean hsm = false;
        try {
            try {
                pqmi = Pqmi.fromEnvironment();
                HsmNodeTls.install(pqmi);
                hsm = true;
            } catch (Exception e) {
                if (!isHsmConnectionFailure(e)) {
                    throw e;
                }
                warn("[!] HSM not reachable: " + hsmFailureSummary(e));
                warn("[!] Software-only: root CA and client CA. "
                        + "Node HSM keys and QuKayDee import skipped.");
                if (pqmi != null) {
                    pqmi.close();
                    pqmi = null;
                }
                SoftwareTls.installSoftware();
            }
            provisionAll(pqmi, config, hsm);
        } finally {
            Arrays.fill(pkcs12Password, '\0');
            if (pqmi != null) {
                pqmi.close();
            }
        }
    }

    /** Connection refused / NO_CONNECTION / missing HSM env — not PIN or keystore errors. */
    static boolean isHsmConnectionFailure(Throwable thrown) {
        for (Throwable cursor = thrown; cursor != null; cursor = cursor.getCause()) {
            String text = (cursor.getClass().getName() + " " + String.valueOf(cursor.getMessage()))
                    .toLowerCase();
            if (text.contains("no_connection")
                    || text.contains("0xbe000015")
                    || text.contains("connectionexception")
                    || text.contains("open_session")
                    || text.contains("connection refused")
                    || text.contains("connection timed out")
                    || cursor instanceof java.net.ConnectException
                    || cursor instanceof java.net.SocketTimeoutException
                    || cursor instanceof java.net.UnknownHostException) {
                return true;
            }
            if (cursor instanceof IllegalStateException
                    && cursor.getMessage() != null
                    && cursor.getMessage().startsWith("Required environment variable not set: HSM_")) {
                return true;
            }
        }
        return false;
    }

    private static void warn(String message) {
        System.out.println(WARN + message + RESET);
    }

    private static String hsmFailureSummary(Throwable thrown) {
        String message = thrown.getMessage();
        return (message == null || message.isBlank()) ? thrown.getClass().getSimpleName() : message;
    }

    private record CaMaterial(KeyPair keys, X509Certificate cert) {}

    private static void provisionAll(Pqmi pqmi, CertGenConfig config, boolean hsm) throws Exception {
        Path certsDir = Path.of(CERTS_DIR);
        Files.createDirectories(certsDir);

        CaMaterial rootCa = loadOrCreateCa(
                certsDir, config.rootCaName(), "CN=PQC-Root-CA, O=CVUT", "Root CA");
        CaMaterial clientCa = loadOrCreateCa(
                certsDir, config.clientCaName(), "CN=PQC-Client-CA, O=CVUT", "Client CA");

        System.out.println("[*] Nodes (" + config.nodes().size() + "): " + String.join(", ", config.nodes()));
        if (!hsm) {
            warn("   [skip] HSM required for node identity keys/PEMs");
        } else {
            for (String node : config.nodes()) {
                provisionNodeIdentity(pqmi, rootCa, node, certsDir);
            }
        }

        if (!hsm) {
            warn("[*] QuKayDee PKCS#12 import skipped (no HSM)");
        } else {
            importQkdKeysIfPresent();
        }
        System.out.println(hsm
                ? "[SUCCESS] Provision complete."
                : "[SUCCESS] Software provision complete (HSM steps skipped).");
    }

    /**
     * Imports {@code certs/qkd/*-client.p12} into CryptoServer.
     * Keys are not generated in the HSM; missing aliases only. PKCS#12 files are left on disk.
     */
    private static void importQkdKeysIfPresent() throws Exception {
        Path qkdDir = Path.of(QKD_DIR);
        if (!Files.isDirectory(qkdDir)) {
            System.out.println("[*] No " + qkdDir + " — skipping QuKayDee PKCS#12 import");
            return;
        }

        List<Path> clientPkcs12Files;
        try (Stream<Path> entries = Files.list(qkdDir)) {
            clientPkcs12Files = entries
                    .filter(Files::isRegularFile)
                    .filter(p -> QKD_CLIENT_P12.matcher(p.getFileName().toString()).matches())
                    .sorted()
                    .toList();
        }
        if (clientPkcs12Files.isEmpty()) {
            System.out.println("[*] No *-client.p12 in " + qkdDir + " — skipping QuKayDee PKCS#12 import");
            return;
        }

        System.out.println("[*] QuKayDee SAE PKCS#12 (" + clientPkcs12Files.size() + ")");
        for (Path pkcs12 : clientPkcs12Files) {
            String alias = aliasFromQkdClientP12(pkcs12);
            System.out.println("-> " + pkcs12.getFileName() + " as HSM alias '" + alias + "'");
            if (hsmAliasExists(alias)) {
                System.out.println("   [skip] already present");
                continue;
            }
            HsmKeyImporter.importPkcs12(alias, pkcs12, pkcs12Password);
            System.out.println("   [SUCCESS] imported");
        }
    }

    private static String aliasFromQkdClientP12(Path pkcs12) {
        String name = pkcs12.getFileName().toString();
        var matcher = QKD_CLIENT_P12.matcher(name);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Not a QKD client PKCS#12: " + name);
        }
        return matcher.group(1);
    }

    private static boolean hsmAliasExists(String alias) throws Exception {
        return HsmGate.call(() -> {
            KeyStore hsm = KeyStore.getInstance("CryptoServer", HsmNodeTls.requireCryptoServer());
            hsm.load(null, null);
            return hsm.containsAlias(alias);
        });
    }

    private static CaMaterial loadOrCreateCa(Path certsDir, String name, String dn, String label)
            throws Exception {
        Path caDir = certsDir.resolve(CA_DIR);
        Files.createDirectories(caDir);
        Path p12Path = caDir.resolve(name + ".p12");
        Path pemPath = caDir.resolve(name + ".pem");
        CaMaterial material;
        if (Files.isRegularFile(p12Path)) {
            System.out.println("[!] Existing " + label + " found. Loading " + p12Path + " ...");
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            try (FileInputStream fis = new FileInputStream(p12Path.toFile())) {
                ks.load(fis, pkcs12Password);
            }
            PrivateKey caPriv = (PrivateKey) ks.getKey("ca", pkcs12Password);
            X509Certificate caCert = (X509Certificate) ks.getCertificate("ca");
            material = new CaMaterial(new KeyPair(caCert.getPublicKey(), caPriv), caCert);
        } else {
            System.out.println("[*] No " + label + " found. Generating NEW " + label + " (ML-DSA)...");
            KeyPair caKeys = generatePqcKeyPair();
            X509Certificate caCert = createCa(caKeys, dn);
            save(p12Path.toString(), "ca", caKeys.getPrivate(), caCert);
            System.out.println("[+] New " + label + " saved to " + p12Path);
            material = new CaMaterial(caKeys, caCert);
        }
        exportCertPem(material.cert(), pemPath.toString());
        return material;
    }

    private static void provisionNodeIdentity(
            Pqmi pqmi, CaMaterial rootCa, String rawName, Path certsDir
    ) throws Exception {
        String name = SoftwareTls.certNameForNode(CertGenConfig.token(rawName, "CERTGEN_NODES"));
        Pqmi.KeyRef keyRef = pqmi.keyRefForNode(name);
        Path pem = certsDir.resolve(name + ".pem");
        boolean keyExists = pqmi.identityKeyExists(keyRef);
        boolean pemExists = Files.isRegularFile(pem);
        System.out.println("-> node " + name + " (HSM " + keyRef.group() + "/" + keyRef.name() + ")");
        if (keyExists && pemExists) {
            if (issuedBy(readCert(pem), rootCa.cert())) {
                System.out.println("   [skip] HSM key and " + pem.getFileName() + " already present");
                return;
            }
            warn("   [!] " + pem.getFileName() + " is not signed by the current Root CA — re-issuing");
        }
        if (!keyExists) {
            pqmi.generateIdentityKey(keyRef, false);
            System.out.println("   [+] PQMI ML-DSA key generated");
        }
        byte[] rawPk = pqmi.exportPublicKey(keyRef);
        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "BC");
        PublicKey nodePub = kf.generatePublic(new MLDSAPublicKeySpec(ML_DSA_PARAM, rawPk));
        X509Certificate nodeCert = issuePurePqcFromPublicKey(rootCa.cert(), rootCa.keys(), nodePub, name);
        exportCertPem(nodeCert, pem.toString());
        System.out.println("   [SUCCESS] " + pem);
    }

    /**
     * Issue a client-CA leaf from a raw ML-DSA-44 public key (on-chip device CSR).
     * Used by UserApp INIT LAB; CertGenerator's main path does not sign device CSRs.
     */
    public static X509Certificate signRawMlDsa44Leaf(Path caP12, String password, byte[] rawPub, String cn)
            throws Exception {
        return SoftwareLeaf.signRawMlDsa44Leaf(caP12, password, rawPub, cn);
    }

    public static void writeCertPem(X509Certificate cert, Path path) throws Exception {
        SoftwareLeaf.writeCertPem(cert, path);
    }

    private static X509Certificate readCert(Path pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
        try (FileInputStream fis = new FileInputStream(pem.toFile())) {
            return (X509Certificate) factory.generateCertificate(fis);
        }
    }

    /**
     * A leaf outlives the CA that signed it: the bundle files are still there, so provisioning
     * skips them, and the mismatch only shows up as a TLS handshake failure at the far end.
     */
    private static boolean issuedBy(X509Certificate cert, X509Certificate ca) {
        if (!cert.getIssuerX500Principal().equals(ca.getSubjectX500Principal())) {
            return false;
        }
        try {
            cert.verify(ca.getPublicKey(), "BC");
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static KeyPair generatePqcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(ML_DSA_PARAM, new SecureRandom());
        return kpg.generateKeyPair();
    }

    private static String signerAlgorithmFor(KeyPair keys) {
        return keys.getPrivate().getAlgorithm();
    }

    private static X509Certificate createCa(KeyPair keys, String dn) throws Exception {
        X500Name name = new X500Name(dn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + 31536000000L),
                name, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, (ASN1Encodable) new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder(signerAlgorithmFor(keys)).setProvider("BC").build(keys.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static X509Certificate issuePurePqcFromPublicKey(
            X509Certificate ca, KeyPair caKeys, PublicKey nodePub, String name
    ) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                ca, BigInteger.valueOf(System.currentTimeMillis()), new Date(),
                new Date(System.currentTimeMillis() + 31536000000L),
                new X500Name("CN=" + name), nodePub);
        ContentSigner signer = new JcaContentSignerBuilder(signerAlgorithmFor(caKeys)).setProvider("BC").build(caKeys.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static void exportCertPem(X509Certificate cert, String path) throws Exception {
        File out = new File(path);
        File parent = out.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(b64.getBytes());
            fos.write("\n-----END CERTIFICATE-----\n".getBytes());
        }
    }

    private static void save(String file, String alias, PrivateKey pk, X509Certificate cert, X509Certificate... chain)
            throws Exception {
        File out = new File(file);
        File parent = out.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        java.security.cert.Certificate[] certificateChain = new java.security.cert.Certificate[1 + chain.length];
        certificateChain[0] = cert;
        System.arraycopy(chain, 0, certificateChain, 1, chain.length);
        ks.setKeyEntry(alias, pk, pkcs12Password, certificateChain);
        try (FileOutputStream fos = new FileOutputStream(out)) {
            ks.store(fos, pkcs12Password);
        }
    }
}
