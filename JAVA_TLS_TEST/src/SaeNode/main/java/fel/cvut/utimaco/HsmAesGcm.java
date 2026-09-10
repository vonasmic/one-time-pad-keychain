package fel.cvut.utimaco;

import CryptoServerJCE.CryptoServerProvider;
import fel.cvut.tls.NodeTls;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * AES-256-GCM encrypt/decrypt via Utimaco CryptoServer JCE.
 * Uses a single HSM-resident AES key (auto-created on first use).
 */
public final class HsmAesGcm {

    public static final String KEY_ALIAS = "shared-key-aes";
    public static final int AES_KEY_BITS = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_BITS = 128;

    private final String keyAlias;
    private final SecureRandom secureRandom = new SecureRandom();

    public HsmAesGcm() {
        this(KEY_ALIAS);
    }

    public HsmAesGcm(String keyAlias) {
        this.keyAlias = Objects.requireNonNull(keyAlias, "keyAlias must not be null");
        if (keyAlias.isBlank()) {
            throw new IllegalArgumentException("keyAlias must not be blank");
        }
    }

    public String keyAlias() {
        return keyAlias;
    }

    /**
     * Ensures an AES-256 key exists in the CryptoServer keystore under {@link #keyAlias()}.
     */
    public void ensureKey() throws Exception {
        HsmGate.run(() -> {
            CryptoServerProvider cs = NodeTls.requireCryptoServer();
            KeyStore ks = KeyStore.getInstance("CryptoServer", cs);
            ks.load(null, null);
            if (ks.containsAlias(keyAlias)) {
                Key existing = ks.getKey(keyAlias, null);
                if (existing instanceof SecretKey) {
                    return;
                }
                throw new IllegalStateException(
                        "HSM alias exists but is not an AES secret key: " + keyAlias);
            }
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", cs);
            keyGenerator.init(AES_KEY_BITS);
            SecretKey secretKey = keyGenerator.generateKey();
            ks.setKeyEntry(keyAlias, secretKey, null, null);
        });
    }

    public SealedBlob encrypt(byte[] plaintext) throws Exception {
        ensureKey();
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        return HsmGate.call(() -> {
            SecretKey key = loadSecretKey(keyAlias);
            CryptoServerProvider cs = NodeTls.requireCryptoServer();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", cs);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return new SealedBlob(ciphertext, iv, GCM_TAG_BITS, keyAlias);
        });
    }

    public byte[] decrypt(SealedBlob sealed) throws Exception {
        sealed.verify();

        return HsmGate.call(() -> {
            SecretKey key = loadSecretKey(sealed.hsmKeyAlias());
            CryptoServerProvider cs = NodeTls.requireCryptoServer();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", cs);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(sealed.gcmTagBits(), sealed.gcmIv()));
            return cipher.doFinal(sealed.ciphertext());
        });
    }

    private SecretKey loadSecretKey(String alias) throws Exception {
        CryptoServerProvider cs = NodeTls.requireCryptoServer();
        KeyStore ks = KeyStore.getInstance("CryptoServer", cs);
        ks.load(null, null);
        Key key = ks.getKey(alias, null);
        if (key == null) {
            throw new IllegalStateException("HSM key alias does not exist: " + alias);
        }
        if (!(key instanceof SecretKey secretKey)) {
            throw new IllegalStateException("HSM alias exists but is not an AES SecretKey: " + alias);
        }
        return secretKey;
    }

    /**
     * AES-GCM sealed payload fields persisted in {@code shared_key_material}.
     */
    public record SealedBlob(
            byte[] ciphertext,
            byte[] gcmIv,
            int gcmTagBits,
            String hsmKeyAlias
    ) {
        public SealedBlob {
            Objects.requireNonNull(ciphertext, "ciphertext must not be null");
            Objects.requireNonNull(gcmIv, "gcmIv must not be null");
            Objects.requireNonNull(hsmKeyAlias, "hsmKeyAlias must not be null");
            if (hsmKeyAlias.isBlank()) {
                throw new IllegalArgumentException("hsmKeyAlias must not be blank");
            }
        }

        public void verify() {
            if (gcmTagBits != GCM_TAG_BITS) {
                throw new IllegalArgumentException("Unsupported GCM tag bits: " + gcmTagBits);
            }
            if (gcmIv.length != GCM_IV_LENGTH) {
                throw new IllegalArgumentException("Unexpected GCM IV length: " + gcmIv.length);
            }
        }
    }
}
