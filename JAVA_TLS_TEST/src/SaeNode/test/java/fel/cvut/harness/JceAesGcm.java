package fel.cvut.harness;

import fel.cvut.utimaco.HsmAesGcm;
import org.mockito.Mockito;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * JDK AES-GCM used only as a Mockito stand-in for {@link HsmAesGcm} in tests.
 * Production {@link HsmAesGcm} still requires CryptoServer and must not use this path.
 */
public final class JceAesGcm {

    public static final String ALIAS = HsmAesGcm.KEY_ALIAS;

    private static final SecretKey KEY = new SecretKeySpec(new byte[32], "AES");
    private static final SecureRandom RANDOM = new SecureRandom();

    private JceAesGcm() {
    }

    public static HsmAesGcm mockHsm() {
        HsmAesGcm hsm = Mockito.mock(HsmAesGcm.class);
        try {
            when(hsm.keyAlias()).thenReturn(ALIAS);
            when(hsm.encrypt(any())).thenAnswer(invocation -> encrypt(invocation.getArgument(0)));
            when(hsm.decrypt(any())).thenAnswer(invocation -> decrypt(invocation.getArgument(0)));
            Mockito.doNothing().when(hsm).ensureKey();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to stub HsmAesGcm", ex);
        }
        return hsm;
    }

    public static HsmAesGcm.SealedBlob encrypt(byte[] plaintext) throws Exception {
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        byte[] iv = new byte[HsmAesGcm.GCM_IV_LENGTH];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, KEY, new GCMParameterSpec(HsmAesGcm.GCM_TAG_BITS, iv));
        return new HsmAesGcm.SealedBlob(cipher.doFinal(plaintext), iv, HsmAesGcm.GCM_TAG_BITS, ALIAS);
    }

    public static byte[] decrypt(HsmAesGcm.SealedBlob sealed) throws Exception {
        sealed.verify();
        if (!ALIAS.equals(sealed.hsmKeyAlias())) {
            throw new IllegalStateException("HSM key alias does not exist: " + sealed.hsmKeyAlias());
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                KEY,
                new GCMParameterSpec(sealed.gcmTagBits(), sealed.gcmIv())
        );
        return cipher.doFinal(sealed.ciphertext());
    }

    public static byte[] flipByte(byte[] input, int index) {
        byte[] copy = Arrays.copyOf(input, input.length);
        copy[index] = (byte) (copy[index] ^ 0x01);
        return copy;
    }
}
