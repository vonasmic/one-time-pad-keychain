package fel.cvut.qkd;

import fel.cvut.tls.NodeTls;
import fel.cvut.utimaco.Pqmi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * QuKayDee ETSI 014 round-trip using HSM-backed SAE client keys (CryptoServer JCE).
 * Requires prior CertGenerator option 2 (QKD PKCS#12 → HSM) and {@code env/hsm.env}.
 */
public class Qkd014Demo {

    public static void main(String[] args) throws Exception {
        String masterBaseUrl = resolveMasterBaseUrl();
        String slaveBaseUrl = System.getProperty("qkd.slaveBaseUrl", defaultSlaveBaseUrl(masterBaseUrl));
        String slaveSaeId = System.getProperty("qkd.slaveSaeId", "sae-2");
        String masterSaeId = System.getProperty("qkd.masterSaeId", "sae-1");
        String masterAlias = System.getProperty("qkd.masterHsmAlias", "sae-1");
        String slaveAlias = System.getProperty("qkd.slaveHsmAlias", "sae-2");

        System.out.println("qkd.baseUrl (master / enc_keys)=" + masterBaseUrl);
        System.out.println("qkd.slaveBaseUrl (slave / dec_keys)=" + slaveBaseUrl);

        Path trustStore = resolveExistingPath("qkd.truststore", "certs/qkd/qkd-server-ca.p12");
        char[] trustPassword = System.getProperty("qkd.truststorePassword", "password").toCharArray();
        NodeTls.TlsProfile tlsProfile = NodeTls.TlsProfile.CLASSICAL;

        try (Pqmi pqmi = Pqmi.fromEnvironment()) {
            Qkd014Client masterClient = Qkd014Client.fromHsm(
                    pqmi, masterBaseUrl, masterAlias, trustStore, trustPassword, tlsProfile);

            KeyContainer encKeys = masterClient.getKey(slaveSaeId, 1, null);
            if (encKeys == null || encKeys.keys == null || encKeys.keys.isEmpty()) {
                System.out.println("No keys returned from Get key.");
                return;
            }

            String keyId = encKeys.keys.get(0).key_ID;
            System.out.println("Get key returned key_ID: " + keyId);

            Qkd014Client slaveClient = Qkd014Client.fromHsm(
                    pqmi, slaveBaseUrl, slaveAlias, trustStore, trustPassword, tlsProfile);
            KeyContainer decKeys = slaveClient.getKeyWithKeyIds(masterSaeId, List.of(keyId));
            int returned = decKeys == null || decKeys.keys == null ? 0 : decKeys.keys.size();
            System.out.println("Get key with key IDs returned key count: " + returned);
        }
    }

    private static Path resolveExistingPath(String propertyName, String defaultRelativePath) throws Exception {
        String configured = System.getProperty(propertyName);
        Path path = Path.of(configured == null ? defaultRelativePath : configured);
        if (!path.isAbsolute()) {
            path = Path.of(System.getProperty("user.dir")).resolve(path).normalize();
        }
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException(
                    "Missing truststore file: " + path + System.lineSeparator()
                            + "user.dir=" + System.getProperty("user.dir") + System.lineSeparator()
                            + "Set working directory to JAVA_TLS_TEST, or -D" + propertyName + "=<path>."
            );
        }
        System.out.println(propertyName + "=" + path);
        return path;
    }

    private static String defaultSlaveBaseUrl(String masterBaseUrl) {
        if (masterBaseUrl.contains("kme-1.")) {
            return masterBaseUrl.replace("kme-1.", "kme-2.");
        }
        return masterBaseUrl;
    }

    private static String resolveMasterBaseUrl() {
        String fromProperty = System.getProperty("qkd.baseUrl");
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty.trim();
        }
        String fromEnv = System.getenv("QKD_BASE_URL");
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv.trim();
        }
        throw new IllegalStateException(
                "Set qkd.baseUrl or QKD_BASE_URL (see .env.example and certs/qkd/README.md)."
        );
    }
}
