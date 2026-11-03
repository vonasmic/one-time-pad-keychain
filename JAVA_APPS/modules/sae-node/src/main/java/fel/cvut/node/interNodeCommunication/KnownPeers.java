package fel.cvut.node.interNodeCommunication;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Pinned RMI peers: SAE ID to SHA-384 of the leaf certificate's SubjectPublicKeyInfo.
 *
 * <p>The pins come from the {@code spkiSha384} field of the SAE directory ({@link SaeNodes}).
 * The local node's own leaf is always accepted as {@code selfSaeId} (self-connections to the
 * local registry).
 */
public final class KnownPeers {

    private static final HexFormat HEX = HexFormat.of();

    private final String selfSaeId;
    private final Map<String, String> saeIdByFingerprint;

    private KnownPeers(String selfSaeId, Map<String, String> saeIdByFingerprint) {
        this.selfSaeId = requireId(selfSaeId, "selfSaeId");
        this.saeIdByFingerprint = Map.copyOf(saeIdByFingerprint);
    }

    /** @param fingerprintBySaeId SAE ID to SPKI SHA-384 hex */
    public static KnownPeers of(String selfSaeId, Map<String, String> fingerprintBySaeId) {
        Objects.requireNonNull(fingerprintBySaeId, "fingerprintBySaeId must not be null");
        Map<String, String> byFingerprint = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : fingerprintBySaeId.entrySet()) {
            String saeId = requireId(e.getKey(), "saeId");
            String fp = normalizeFingerprint(e.getValue());
            if (byFingerprint.put(fp, saeId) != null) {
                throw new IllegalArgumentException("Duplicate pinned fingerprint for SAE " + saeId);
            }
        }
        return new KnownPeers(selfSaeId, byFingerprint);
    }

    /** Pins of every SAE in {@code nodes}. */
    public static KnownPeers from(String selfSaeId, SaeNodes nodes) {
        Objects.requireNonNull(nodes, "nodes must not be null");
        Map<String, String> bySae = new LinkedHashMap<>();
        for (SaeNodes.Entry e : nodes.entries()) {
            bySae.put(e.saeId(), e.spkiSha384());
        }
        return of(selfSaeId, bySae);
    }

    public String selfSaeId() {
        return selfSaeId;
    }

    /** SAE ID pinned for this leaf, if any (does not consider the local leaf). */
    public Optional<String> saeIdFor(Certificate leaf) {
        if (leaf == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(saeIdByFingerprint.get(spkiSha384(leaf)));
    }

    public static String spkiSha384(Certificate cert) {
        Objects.requireNonNull(cert, "cert must not be null");
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-384").digest(cert.getPublicKey().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    private static String normalizeFingerprint(String value) {
        String fp = Objects.toString(value, "").trim().replace(":", "").toLowerCase(Locale.ROOT);
        if (fp.length() != 96 || !fp.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            throw new IllegalArgumentException("spkiSha384 must be 96 hex characters");
        }
        return fp;
    }

    private static String requireId(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value.trim();
    }
}
