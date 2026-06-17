package fel.cvut.qkd;

import fel.cvut.bouncyCastle.BouncyCastleTLS;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class Qkd014Demo {

    public static void main(String[] args) throws Exception {
        String masterBaseUrl = resolveMasterBaseUrl();
        String slaveBaseUrl = System.getProperty("qkd.slaveBaseUrl", defaultSlaveBaseUrl(masterBaseUrl));
        String slaveSaeId = System.getProperty("qkd.slaveSaeId", "sae-2");
        String masterSaeId = System.getProperty("qkd.masterSaeId", "sae-1");

        System.out.println("qkd.baseUrl (master / enc_keys)=" + masterBaseUrl);
        System.out.println("qkd.slaveBaseUrl (slave / dec_keys)=" + slaveBaseUrl);

        Path masterKeyStore = resolveExistingPath("qkd.clientKeystore", "certs/qkd/sae-1-client.p12");
        Path slaveKeyStore = resolveExistingPath("qkd.slaveClientKeystore", "certs/qkd/sae-2-client.p12");
        Path trustStore = resolveExistingPath("qkd.truststore", "certs/qkd/qkd-server-ca.p12");
        char[] clientPassword = System.getProperty("qkd.clientKeystorePassword", "password").toCharArray();
        char[] trustPassword = System.getProperty("qkd.truststorePassword", "password").toCharArray();

        BouncyCastleTLS.TlsPolicy tlsPolicy = BouncyCastleTLS.TlsPolicy.defaultPolicy();

        // QuKayDee: master (sae-1) → kme-1 enc_keys; slave (sae-2) → kme-2 dec_keys.
        Qkd014Client masterClient = Qkd014Client.fromPkcs12(
                masterBaseUrl,
                masterKeyStore,
                clientPassword,
                trustStore,
                trustPassword,
                tlsPolicy
        );

        KeyContainer encKeys = masterClient.getKey(slaveSaeId, 1, null);
        if (encKeys == null || encKeys.keys == null || encKeys.keys.isEmpty()) {
            System.out.println("No keys returned from Get key.");
            return;
        }

        String keyId = encKeys.keys.get(0).key_ID;
        System.out.println("Get key returned key_ID: " + keyId);

        Qkd014Client slaveClient = Qkd014Client.fromPkcs12(
                slaveBaseUrl,
                slaveKeyStore,
                clientPassword,
                trustStore,
                trustPassword,
                tlsPolicy
        );
        KeyContainer decKeys = slaveClient.getKeyWithKeyIds(masterSaeId, List.of(keyId));
        int returned = decKeys == null || decKeys.keys == null ? 0 : decKeys.keys.size();
        System.out.println("Get key with key IDs returned key count: " + returned);
    }

    private static Path resolveExistingPath(String propertyName, String defaultRelativePath) throws Exception {
        String configured = System.getProperty(propertyName);
        Path path = Path.of(configured == null ? defaultRelativePath : configured);
        if (!path.isAbsolute()) {
            path = Path.of(System.getProperty("user.dir")).resolve(path).normalize();
        }
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException(
                    "Missing keystore file: " + path + System.lineSeparator()
                            + "user.dir=" + System.getProperty("user.dir") + System.lineSeparator()
                            + "Set IntelliJ Run Configuration → Working directory to the JAVA_TLS_TEST folder "
                            + "(the directory that contains pom.xml and certs/qkd/), or pass -D" + propertyName + "=<absolute path>."
            );
        }
        System.out.println(propertyName + "=" + path);
        return path;
    }

    /** QuKayDee default: keys are fetched from kme-1, delivered from kme-2. */
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
