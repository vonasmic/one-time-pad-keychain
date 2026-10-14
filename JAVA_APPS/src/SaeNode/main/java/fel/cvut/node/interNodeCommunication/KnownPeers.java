package fel.cvut.node.interNodeCommunication;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
 * Pinned RMI peers: SAE ID to SHA-256 of the leaf certificate's SubjectPublicKeyInfo.
 *
 * <p>File format ({@code RMI_KNOWN_PEERS}): a JSON array of
 * {@code {"saeId": "sae-2", "spkiSha256": "<64 hex chars>"}}. The local node's own leaf is
 * always accepted as {@code selfSaeId} (self-connections to the local registry).
 */
public final class KnownPeers {

    private static final HexFormat HEX = HexFormat.of();

    private final String selfSaeId;
    private final Map<String, String> saeIdByFingerprint;

    private KnownPeers(String selfSaeId, Map<String, String> saeIdByFingerprint) {
        this.selfSaeId = requireId(selfSaeId, "selfSaeId");
        this.saeIdByFingerprint = Map.copyOf(saeIdByFingerprint);
    }

    /** @param fingerprintBySaeId SAE ID to SPKI SHA-256 hex */
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

    public static KnownPeers load(String selfSaeId, Path file) throws IOException {
        Objects.requireNonNull(file, "file must not be null");
        Row[] rows = new ObjectMapper().readValue(Files.readAllBytes(file), Row[].class);
        Map<String, String> bySae = new LinkedHashMap<>();
        for (Row row : rows) {
            if (row == null || bySae.put(requireId(row.saeId, "saeId"), row.spkiSha256) != null) {
                throw new IllegalArgumentException("Invalid or duplicate row in " + file);
            }
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
        return Optional.ofNullable(saeIdByFingerprint.get(spkiSha256(leaf)));
    }

    public static String spkiSha256(Certificate cert) {
        Objects.requireNonNull(cert, "cert must not be null");
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getPublicKey().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String normalizeFingerprint(String value) {
        String fp = Objects.toString(value, "").trim().replace(":", "").toLowerCase(Locale.ROOT);
        if (fp.length() != 64 || !fp.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            throw new IllegalArgumentException("spkiSha256 must be 64 hex characters");
        }
        return fp;
    }

    private static String requireId(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value.trim();
    }

    private static final class Row {
        public String saeId;
        public String spkiSha256;
    }
}
