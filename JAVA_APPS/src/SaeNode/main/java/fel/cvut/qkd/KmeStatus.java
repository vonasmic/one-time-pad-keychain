package fel.cvut.qkd;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

/**
 * ETSI GS QKD 014 {@code GET .../status} body. {@code *_size} fields are in bits.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class KmeStatus {
    public String source_KME_ID;
    public String target_KME_ID;
    public String master_SAE_ID;
    public String slave_SAE_ID;
    public Integer key_size;
    public Integer stored_key_count;
    public Integer max_key_count;
    public Integer max_key_per_request;
    public Integer max_key_size;
    public Integer min_key_size;
    public Integer max_SAE_ID_count;
    /** Optional vendor/future-use extension object (ETSI GS QKD 014 §6.1). */
    public Map<String, Object> status_extension;

    public int maxKeySizeBits() {
        if (max_key_size == null || max_key_size < 8) {
            throw new IllegalStateException("KME status is missing a usable max_key_size");
        }
        return max_key_size - (max_key_size % 8);
    }

    /**
     * Pool unit width ({@code key_size}). This is what {@code stored_key_count} counts,
     * not {@code max_key_size}. Falls back to {@link #maxKeySizeBits()} if absent.
     */
    public int keySizeBits() {
        if (key_size != null && key_size >= 8) {
            return key_size - (key_size % 8);
        }
        return maxKeySizeBits();
    }

    public int maxKeysPerRequest() {
        if (max_key_per_request == null || max_key_per_request < 1) {
            throw new IllegalStateException("KME status is missing a usable max_key_per_request");
        }
        return max_key_per_request;
    }
}
