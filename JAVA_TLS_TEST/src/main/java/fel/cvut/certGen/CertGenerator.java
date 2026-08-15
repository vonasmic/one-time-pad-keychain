package fel.cvut.certGen;

import fel.cvut.tls.NodeTls;
import fel.cvut.utimaco.Pqmi;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Interactive PKI / HSM provisioning:
 * <ul>
 *   <li>PQC node leaf certs (ML-DSA keys generated in PQMI; PEM on disk)</li>
 *   <li>QuKayDee SAE client keys (import PKCS#12 into CryptoServer; then delete the file)</li>
 *   <li>Full provision (default): all node PEMs → HSM keys + refreshed leaf certs + native client bundle</li>
 * </ul>
 */
public class CertGenerator {
    private static final MLDSAParameterSpec ML_DSA_PARAM = MLDSAParameterSpec.ml_dsa_44;
    private static final String CERTS_DIR = "certs";
    private static final String CA_PEM = CERTS_DIR + "/root-ca.pem";
    private static final String ROOT_CA_PEM = "root-ca.pem";
    private static final String CLIENT_DIR = CERTS_DIR + "/client";
    private static final String NATIVE_CLIENT_CN = "native-tls-client";
    private static final String QKD_DIR = CERTS_DIR + "/qkd";
    private static final Pattern QKD_CLIENT_P12 = Pattern.compile("(.+)-client\\.p12$");
    private static final String DEFAULT_PKCS12_PASSWORD = "password";

    static { Security.addProvider(new BouncyCastleProvider()); }

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("=== FEL CVUT HSM / PKI TOOL ===");
        System.out.println("1) PQC node cert (single node, PQMI ML-DSA)");
        System.out.println("2) Import QuKayDee SAE PKCS#12 into HSM (auto from certs/qkd/, or manual)");
        System.out.println("3) Full provision: all node PEMs → HSM + leaf certs + native client bundle (default)");
        System.out.print("Choice [3]: ");
        String choice = sc.nextLine().trim();
        if (choice.isEmpty()) {
            choice = "3";
        }
        switch (choice) {
            case "1" -> provisionPqcNode(sc);
            case "2" -> importQkdKey(sc);
            default -> provisionAll();
        }
    }

    private static void importQkdKey(Scanner sc) throws Exception {
        if (!autoImportQkdKeysFromFolder(sc)) {
            importQkdKeyManual(sc);
        }
    }

    /**
     * Imports every {@code *-client.p12} under {@link #QKD_DIR} (alias = basename without {@code -client.p12}).
     *
     * @return {@code true} when all discovered files were imported successfully; {@code false} to fall back to manual import
     */
    private static boolean autoImportQkdKeysFromFolder(Scanner sc) throws Exception {
        Path qkdDir = Path.of(QKD_DIR);
        if (!Files.isDirectory(qkdDir)) {
            System.out.println("[!] QKD directory not found: " + qkdDir.toAbsolutePath());
            return false;
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
            System.out.println("[!] No *-client.p12 files in " + qkdDir.toAbsolutePath());
            return false;
        }

        System.out.println("[*] Auto-importing " + clientPkcs12Files.size()
                + " QuKayDee SAE PKCS#12 file(s) from " + qkdDir + " ...");
        char[] password = DEFAULT_PKCS12_PASSWORD.toCharArray();
        List<Path> imported = new ArrayList<>();
        boolean allSucceeded = true;
        try {
            for (Path pkcs12 : clientPkcs12Files) {
                String alias = aliasFromQkdClientP12(pkcs12);
                System.out.println("-> " + pkcs12.getFileName() + " as HSM alias '" + alias + "'");
                try {
                    HsmKeyImporter.importPkcs12(alias, pkcs12, password);
                    System.out.println("   [SUCCESS] Imported into HSM as '" + alias + "'");
                    imported.add(pkcs12);
                } catch (Exception e) {
                    allSucceeded = false;
                    System.out.println("   [FAILED] " + e.getMessage());
                }
            }
        } finally {
            Arrays.fill(password, '\0');
        }

        if (!imported.isEmpty()) {
            System.out.print("Delete imported PKCS#12 file(s)? [Y/n]: ");
            String del = sc.nextLine().trim();
            if (del.isEmpty() || del.equalsIgnoreCase("y")) {
                for (Path pkcs12 : imported) {
                    Files.deleteIfExists(pkcs12);
                    System.out.println("Deleted " + pkcs12);
                }
            }
            System.out.println("Set QKD_HSM_KEY_ALIAS to this node's SAE alias (e.g. sae-1).");
        }

        if (!allSucceeded) {
            System.out.println("[!] Some auto-imports failed — falling back to manual import.");
        }
        return allSucceeded;
    }

    private static String aliasFromQkdClientP12(Path pkcs12) {
        String name = pkcs12.getFileName().toString();
        var matcher = QKD_CLIENT_P12.matcher(name);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Not a QKD client PKCS#12: " + name);
        }
        return matcher.group(1);
    }

    private static void importQkdKeyManual(Scanner sc) throws Exception {
        System.out.println("--- Manual QuKayDee SAE PKCS#12 import ---");
        System.out.print("HSM alias [default sae-1(see .env.example)]: ");
        String alias = sc.nextLine().trim();
        if (alias.isEmpty()) {
            alias = "sae-1";
        }
        System.out.print("PKCS#12 path [" + QKD_DIR + "/" + alias + "-client.p12]: ");
        String pathIn = sc.nextLine().trim();
        Path pkcs12 = Path.of(pathIn.isEmpty() ? QKD_DIR + "/" + alias + "-client.p12" : pathIn);
        if (!Files.isRegularFile(pkcs12)) {
            throw new IllegalStateException("File not found: " + pkcs12);
        }
        System.out.print("PKCS#12 password [" + DEFAULT_PKCS12_PASSWORD + "]: ");
        String passIn = sc.nextLine();
        char[] password = (passIn == null || passIn.isBlank() ? DEFAULT_PKCS12_PASSWORD : passIn.trim()).toCharArray();

        try {
            HsmKeyImporter.importPkcs12(alias, pkcs12, password);
            System.out.println("[SUCCESS] Imported into HSM as '" + alias + "'");
            System.out.print("Delete " + pkcs12 + "? [Y/n]: ");
            String del = sc.nextLine().trim();
            if (del.isEmpty() || del.equalsIgnoreCase("y")) {
                Files.deleteIfExists(pkcs12);
                System.out.println("Deleted " + pkcs12);
            }
            System.out.println("Set QKD_HSM_KEY_ALIAS=" + alias);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private record RootCaMaterial(KeyPair keys, X509Certificate cert) {}

    private static RootCaMaterial loadOrCreateRootCa() throws Exception {
        File caFile = new File(CERTS_DIR + "/root-ca.p12");
        if (caFile.exists()) {
            System.out.println("[!] Existing Root CA found. Loading...");
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            try (FileInputStream fis = new FileInputStream(caFile)) {
                ks.load(fis, "password".toCharArray());
            }
            PrivateKey caPriv = (PrivateKey) ks.getKey("ca", "password".toCharArray());
            X509Certificate caCert = (X509Certificate) ks.getCertificate("ca");
            return new RootCaMaterial(new KeyPair(caCert.getPublicKey(), caPriv), caCert);
        }
        System.out.println("[*] No CA found. Generating NEW Root CA (ML-DSA)...");
        KeyPair caKeys = generatePqcKeyPair(ML_DSA_PARAM);
        X509Certificate caCert = createRootCA(caKeys);
        save(CERTS_DIR + "/root-ca.p12", "ca", caKeys.getPrivate(), caCert);
        System.out.println("[+] New Root CA saved to root-ca.p12");
        return new RootCaMaterial(caKeys, caCert);
    }

    private static void provisionAll() throws Exception {
        RootCaMaterial rootCa = loadOrCreateRootCa();
        exportCertPem(rootCa.cert(), CA_PEM);

        List<String> nodeNames = discoverNodeCertNames();
        if (nodeNames.isEmpty()) {
            System.out.println("[!] No node leaf certs in " + CERTS_DIR
                    + " (expected e.g. Alice.pem, Bob.pem — excluding " + ROOT_CA_PEM + ")");
        } else {
            System.out.println("[*] Provisioning " + nodeNames.size()
                    + " node identity key(s) in HSM from existing leaf cert names...");
            try (Pqmi pqmi = Pqmi.fromEnvironment()) {
                for (String name : nodeNames) {
                    provisionNodeIdentity(pqmi, rootCa, name, false);
                }
            }
        }

        writeNativeClientBundle(rootCa.cert(), rootCa.keys());
        System.out.println("[SUCCESS] Full provision complete.");
    }

    /** Node names from top-level {@code certs/*.pem}, excluding {@link #ROOT_CA_PEM}. */
    private static List<String> discoverNodeCertNames() throws Exception {
        Path certsDir = Path.of(CERTS_DIR);
        if (!Files.isDirectory(certsDir)) {
            return List.of();
        }
        try (Stream<Path> entries = Files.list(certsDir)) {
            return entries
                    .filter(Files::isRegularFile)
                    .map(path -> path.getFileName().toString())
                    .filter(name -> name.endsWith(".pem"))
                    .filter(name -> !ROOT_CA_PEM.equals(name))
                    .map(name -> name.substring(0, name.length() - ".pem".length()))
                    .sorted()
                    .toList();
        }
    }

    private static void provisionNodeIdentity(
            Pqmi pqmi, RootCaMaterial rootCa, String name, boolean overwrite
    ) throws Exception {
        Pqmi.KeyRef keyRef = pqmi.keyRefForNode(name);
        System.out.println("-> " + name + " (HSM " + keyRef.group() + "/" + keyRef.name() + ")");
        if (overwrite) {
            pqmi.generateIdentityKey(keyRef, true);
        } else if (!pqmi.identityKeyExists(keyRef)) {
            pqmi.generateIdentityKey(keyRef, false);
        }
        byte[] rawPk = pqmi.exportPublicKey(keyRef);
        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "BC");
        PublicKey nodePub = kf.generatePublic(new MLDSAPublicKeySpec(ML_DSA_PARAM, rawPk));
        X509Certificate nodeCert = issuePurePqcFromPublicKey(rootCa.cert(), rootCa.keys(), nodePub, name);
        exportCertPem(nodeCert, CERTS_DIR + "/" + name + ".pem");
        System.out.println("   [SUCCESS] " + name + ".pem");
    }

    private static void provisionPqcNode(Scanner sc) throws Exception {
        RootCaMaterial rootCa = loadOrCreateRootCa();
        exportCertPem(rootCa.cert(), CA_PEM);

        System.out.print("\nEnter Node Name (e.g., Alice, Carol): ");
        String name = sc.nextLine().trim();
        if (name.isEmpty()) {
            return;
        }

        System.out.print("Overwrite existing HSM key if present? [y/N]: ");
        boolean overwrite = sc.nextLine().trim().equalsIgnoreCase("y");

        System.out.println("-> Generating Pure PQC node key in HSM (ML-DSA)...");
        try (Pqmi pqmi = Pqmi.fromEnvironment()) {
            provisionNodeIdentity(pqmi, rootCa, name, overwrite);
        }
    }

    private static void writeNativeClientBundle(X509Certificate caCert, KeyPair caKeys) throws Exception {
        System.out.println("-> Generating native TLS client bundle (ML-DSA)...");
        KeyPair clientKeys = generatePqcKeyPair(ML_DSA_PARAM);
        X509Certificate clientCert = issuePurePqc(caCert, caKeys, clientKeys, NATIVE_CLIENT_CN);

        new File(CLIENT_DIR).mkdirs();
        exportCertPem(clientCert, CLIENT_DIR + "/client-cert.pem");
        exportPrivateKeyPem(clientKeys.getPrivate(), CLIENT_DIR + "/client-key.pem");
        System.out.println("[SUCCESS] Wrote " + CLIENT_DIR + "/{client-cert.pem,client-key.pem}");
        System.out.println("         Trust anchor remains " + CA_PEM);
    }

    private static KeyPair generatePqcKeyPair(MLDSAParameterSpec parameterSpec) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(parameterSpec, new SecureRandom());
        return kpg.generateKeyPair();
    }

    private static String signerAlgorithmFor(KeyPair keys) {
        return keys.getPrivate().getAlgorithm();
    }

    private static X509Certificate createRootCA(KeyPair keys) throws Exception {
        X500Name name = new X500Name("CN=PQC-Root-CA, O=CVUT");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + 31536000000L),
                name, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, (ASN1Encodable) new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder(signerAlgorithmFor(keys)).setProvider("BC").build(keys.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static X509Certificate issuePurePqc(X509Certificate ca, KeyPair caKeys, KeyPair nodeKeys, String name)
            throws Exception {
        return issuePurePqcFromPublicKey(ca, caKeys, nodeKeys.getPublic(), name);
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
        out.getParentFile().mkdirs();
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(b64.getBytes());
            fos.write("\n-----END CERTIFICATE-----\n".getBytes());
        }
    }

    private static void exportPrivateKeyPem(PrivateKey key, String path) throws Exception {
        File out = new File(path);
        out.getParentFile().mkdirs();
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded());
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
            fos.write(b64.getBytes());
            fos.write("\n-----END PRIVATE KEY-----\n".getBytes());
        }
    }

    private static void save(String file, String alias, PrivateKey pk, X509Certificate cert, X509Certificate... chain)
            throws Exception {
        new File(file).getParentFile().mkdirs();
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        java.security.cert.Certificate[] certificateChain = new java.security.cert.Certificate[1 + chain.length];
        certificateChain[0] = cert;
        System.arraycopy(chain, 0, certificateChain, 1, chain.length);
        ks.setKeyEntry(alias, pk, "password".toCharArray(), certificateChain);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            ks.store(fos, "password".toCharArray());
        }
    }
}
