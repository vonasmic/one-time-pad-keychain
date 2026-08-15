package fel.cvut.certGen;

import CryptoServerJCE.CryptoServerProvider;
import CryptoServerJCE.CryptoServerProviderBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Enumeration;
import java.util.Objects;

/** One-time QuKayDee SAE PKCS#12 → CryptoServer keystore import (CertGenerator option 2). */
final class HsmKeyImporter {

    private HsmKeyImporter() {
    }

    static void importPkcs12(String alias, Path pkcs12Path, char[] password) throws Exception {
        Objects.requireNonNull(alias, "alias must not be null");

        CryptoServerProvider cryptoServer = openCryptoServer();
        try {
            KeyStore soft = loadPkcs12(pkcs12Path, password);
            String softAlias = findKeyAlias(soft);
            PrivateKey softKey = (PrivateKey) soft.getKey(softAlias, password);
            Certificate[] chain = soft.getCertificateChain(softAlias);
            if (softKey == null || chain == null || chain.length == 0) {
                throw new IllegalStateException("No private key entry in: " + pkcs12Path);
            }

            KeySpec importSpec = hsmImportKeySpec(softKey);
            KeyFactory kf = KeyFactory.getInstance(softKey.getAlgorithm(), cryptoServer);
            PrivateKey hsmKey = kf.generatePrivate(importSpec);

            KeyStore hsm = KeyStore.getInstance("CryptoServer", cryptoServer);
            hsm.load(null, null);
            if (hsm.containsAlias(alias)) {
                hsm.deleteEntry(alias);
            }
            hsm.setKeyEntry(alias, hsmKey, null, chain);
        } finally {
            cryptoServer.close();
        }
    }

    private static CryptoServerProvider openCryptoServer() throws Exception {
        CryptoServerProvider cs = new CryptoServerProviderBuilder()
                .device(requireEnv("HSM_DEVICE"))
                .timeout(Integer.parseInt(requireEnv("HSM_TIMEOUT_MS")))
                .connectionTimeout(3000)
                .build();
        cs.loginPassword(requireEnv("HSM_USER"), requireEnv("HSM_PIN"));
        return cs;
    }

    private static KeyStore loadPkcs12(Path keyStorePath, char[] keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        try (var in = Files.newInputStream(keyStorePath)) {
            keyStore.load(in, keyStorePassword);
        } catch (IOException e) {
            throw new IOException("Failed to load PKCS12 store: " + keyStorePath, e);
        }
        return keyStore;
    }

    private static KeySpec hsmImportKeySpec(PrivateKey softKey) throws Exception {
        KeyFactory softKf = KeyFactory.getInstance(softKey.getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
        return switch (softKey.getAlgorithm()) {
            case "RSA" -> softKey instanceof RSAPrivateCrtKey
                    ? softKf.getKeySpec(softKey, RSAPrivateCrtKeySpec.class)
                    : softKf.getKeySpec(softKey, RSAPrivateKeySpec.class);
            case "EC", "ECDSA" -> softKf.getKeySpec(softKey, ECPrivateKeySpec.class);
            default -> throw new IllegalStateException(
                    "Unsupported key algorithm for HSM import: " + softKey.getAlgorithm());
        };
    }

    private static String findKeyAlias(KeyStore ks) throws Exception {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a)) {
                return a;
            }
        }
        throw new IllegalStateException("No key entry in keystore");
    }

    private static String requireEnv(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException("Required environment variable not set: " + name);
        }
        return v.trim();
    }
}
