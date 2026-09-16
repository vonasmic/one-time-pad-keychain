package fel.cvut.se;

/**
 * Wire and crypto sizes matching SE firmware ({@code secure_lv.h}, {@code se_tropic_rmem.h},
 * {@code se_tropic_mlkem.h}, {@code se_tropic_session.h}).
 */
public final class SeConstants {

    public static final int LV_DOWNLINK_VERSION = 2;
    public static final int LV_UPLINK_VERSION = 4;
    public static final int LV_UPLINK_FIXED_ITEMS = 7;
    /** Downlink v2 item 1: which pad half this device uses for decrypt. */
    public static final int DECRYPT_HALF_LEN = 1;
    public static final byte DECRYPT_HALF_ORIGIN = 0;
    public static final byte DECRYPT_HALF_PEER = 1;

    public static final int EXPORTER_LEN = 32;
    /** RFC 9266 name for {@link org.bouncycastle.jsse.BCSSLConnection#getChannelBinding}. */
    public static final String CHANNEL_BINDING = "tls-exporter";
    /** HKDF label used by wolfSSL / BC for {@link #CHANNEL_BINDING}. */
    public static final String EXPORTER_LABEL = "EXPORTER-Channel-Binding";

    public static final int SESSION_SIG_LEN = 64;
    public static final int ECC_PUB_LEN = 64;
    /** SHA-384 of {@code spki || ecc_pub}. */
    public static final int CLIENT_HASH_LEN = 48;
    public static final int FILL_ID_LEN = 32;
    /** SHA-384 of a peer SPKI. */
    public static final int PEER_HASH_LEN = 48;

    public static final int MLKEM_PK_LEN = 1184;
    public static final int MLKEM_CT_LEN = 1088;
    public static final int MLKEM_SS_LEN = 32;

    public static final int RMEM_AES_KEY_LEN = 32;
    public static final int RMEM_NONCE_LEN = 12;
    public static final int RMEM_TAG_LEN = 16;
    public static final int RMEM_VER = 1;
    /** version(1) + nonce(12) + tag(16). */
    public static final int RMEM_OVERHEAD = 1 + RMEM_NONCE_LEN + RMEM_TAG_LEN;

    public static final int PAD_COUNT = 507;
    public static final int RMEM_SLOT_MAX = 475;

    /** Max sum of downlink key payload bytes (framing not counted). Matches firmware. */
    public static final int QKD_MAX_BYTES = MLKEM_CT_LEN + PAD_COUNT * RMEM_SLOT_MAX;

    public static final int PIN_SIZE_MIN = 4;
    public static final int PIN_SIZE_MAX = 8;

    public static final String SLOT_LABEL = "SE_tropic_qkd_slot_v3";

    private SeConstants() {
    }
}
