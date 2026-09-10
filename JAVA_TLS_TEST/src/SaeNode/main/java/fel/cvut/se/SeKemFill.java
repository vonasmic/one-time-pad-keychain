package fel.cvut.se;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * SAE-side ML-KEM-768 encapsulation and per-slot AES-GCM pad sealing for the TLS downlink.
 *
 * <p>The pad-fill public key comes from the session uplink (item 6), not a pre-share.
 * Origin and peer both call this with the same QKD bytes; only {@code decryptHalf} differs.
 * A partial fill is split 50/50 across firmware halves ({@code padCount / 2}).
 */
public final class SeKemFill {

    private final SecureRandom random;

    public SeKemFill() {
        this(new SecureRandom());
    }

    public SeKemFill(SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random must not be null");
    }

    /**
     * Encapsulates against {@link SeSessionUplink#mlkemPublicKey()}, seals pads, and returns
     * LV downlink version 2 bytes ({@code kem_ct}, {@code decrypt_half}, then sealed pad images).
     *
     * @param decryptHalf {@link SeConstants#DECRYPT_HALF_ORIGIN} or {@link SeConstants#DECRYPT_HALF_PEER}
     */
    public byte[] buildDownlink(SeSessionUplink uplink, List<String> base64Keys, byte decryptHalf) {
        Objects.requireNonNull(uplink, "uplink must not be null");
        if (decryptHalf != SeConstants.DECRYPT_HALF_ORIGIN
                && decryptHalf != SeConstants.DECRYPT_HALF_PEER) {
            throw new IllegalArgumentException("decryptHalf must be 0 or 1: " + decryptHalf);
        }
        byte[] plaintext = SeBytes.decodeAndConcatBase64(base64Keys);
        int plainMax = uplink.plainMax();
        int n = Math.min(uplink.maxPadsForBudget(), plaintext.length / plainMax);
        if (n <= 0) {
            throw new IllegalArgumentException(
                    "Not enough QKD material or downlink budget for any pad "
                            + "(bytes=" + plaintext.length + ", plainMax=" + plainMax
                            + ", maxPads=" + uplink.maxPadsForBudget() + ")");
        }

        int half = uplink.padCount() / 2;
        int first = n / 2;
        int second = n - first;

        MLKEMPublicKeyParameters pub =
                new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, uplink.mlkemPublicKey());
        SecretWithEncapsulation secret = new MLKEMGenerator(random).generateEncapsulated(pub);
        byte[] kemCt = secret.getEncapsulation();
        byte[] rawSs = secret.getSecret();
        if (kemCt.length != SeConstants.MLKEM_CT_LEN) {
            throw new IllegalStateException("Unexpected ML-KEM CT length: " + kemCt.length);
        }
        if (rawSs.length < SeConstants.MLKEM_SS_LEN) {
            throw new IllegalStateException("Unexpected ML-KEM SS length: " + rawSs.length);
        }
        byte[] ss = Arrays.copyOf(rawSs, SeConstants.MLKEM_SS_LEN);

        List<byte[]> items = new ArrayList<>(2 + half + second);
        items.add(kemCt);
        items.add(new byte[] {decryptHalf});
        int src = 0;
        for (int logical = 0; logical < first; logical++) {
            items.add(sealPad(ss, uplink.fillId(), logical, plaintext, src * plainMax, plainMax));
            src++;
        }
        for (int logical = first; logical < half; logical++) {
            items.add(new byte[0]);
        }
        for (int i = 0; i < second; i++) {
            int logical = half + i;
            items.add(sealPad(ss, uplink.fillId(), logical, plaintext, src * plainMax, plainMax));
            src++;
        }
        return SecureLv.encode(SeConstants.LV_DOWNLINK_VERSION, items);
    }

    private byte[] sealPad(byte[] ss, byte[] fillId, int logical, byte[] plaintext, int off, int plainMax) {
        byte[] plain = Arrays.copyOfRange(plaintext, off, off + plainMax);
        return aeadSeal(slotKey(ss, fillId, logical), logical, plain);
    }

    /** Package-visible for tests. */
    static byte[] slotKey(byte[] ss, byte[] fillId, int logicalSlot) {
        byte[] label = SeConstants.SLOT_LABEL.getBytes(StandardCharsets.US_ASCII);
        byte[] info = new byte[label.length + SeConstants.FILL_ID_LEN + 2];
        System.arraycopy(label, 0, info, 0, label.length);
        System.arraycopy(fillId, 0, info, label.length, SeConstants.FILL_ID_LEN);
        info[label.length + SeConstants.FILL_ID_LEN] = (byte) (logicalSlot & 0xFF);
        info[label.length + SeConstants.FILL_ID_LEN + 1] = (byte) ((logicalSlot >>> 8) & 0xFF);

        byte[] salt = new byte[48]; // HashLen zeros, matching wolfSSL NULL salt
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA384Digest());
        hkdf.init(new HKDFParameters(ss, salt, info));
        byte[] key = new byte[SeConstants.RMEM_AES_KEY_LEN];
        hkdf.generateBytes(key, 0, key.length);
        return key;
    }

    private byte[] aeadSeal(byte[] key, int logicalSlot, byte[] plain) {
        try {
            byte[] nonce = new byte[SeConstants.RMEM_NONCE_LEN];
            random.nextBytes(nonce);
            byte[] aad = SeBytes.u16Le(logicalSlot);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(SeConstants.RMEM_TAG_LEN * 8, nonce)
            );
            cipher.updateAAD(aad);
            byte[] ctAndTag = cipher.doFinal(plain);

            byte[] image = new byte[SeConstants.RMEM_OVERHEAD + plain.length];
            image[0] = (byte) SeConstants.RMEM_VER;
            System.arraycopy(nonce, 0, image, 1, SeConstants.RMEM_NONCE_LEN);
            System.arraycopy(ctAndTag, 0, image, 1 + SeConstants.RMEM_NONCE_LEN, ctAndTag.length);
            return image;
        } catch (Exception ex) {
            throw new IllegalStateException("AES-GCM seal failed", ex);
        }
    }
}
