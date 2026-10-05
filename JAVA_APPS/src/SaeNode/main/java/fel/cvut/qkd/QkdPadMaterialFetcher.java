package fel.cvut.qkd;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeSessionUplink;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Fetches ETSI 014 key material for pad slots advertised by the SE uplink.
 *
 * <p>{@code size} is always {@code max_key_size} from {@code GET /status}, aligned down
 * to the pool unit {@code key_size}. There is no compiled-in size cap. {@code GET /status}
 * is used at start, when the local pool estimate cannot cover another packed key, or
 * after “not enough key material”. If the pool does not replenish in time, a partial
 * fetch of at least two pads is returned so {@link fel.cvut.se.SeKemFill} can split
 * encrypt/decrypt 50/50.
 */
public final class QkdPadMaterialFetcher {

    private static final Logger LOG = Logger.getLogger(QkdPadMaterialFetcher.class.getName());

    static final int MIN_PARTIAL_PADS = 2;

    static final Duration DEFAULT_POLL = Duration.ofSeconds(1);
    static final Duration DEFAULT_DEADLINE = Duration.ofSeconds(10);

    public record FetchedKeys(List<String> keyIds, List<String> keyMaterial) {
        public FetchedKeys {
            keyIds = List.copyOf(keyIds);
            keyMaterial = List.copyOf(keyMaterial);
        }
    }

    @FunctionalInterface
    interface Sleeper {
        void sleep(Duration duration) throws InterruptedException;
    }

    private final Qkd014Client qkdClient;
    private final Sleeper sleeper;
    private final Duration poll;
    private final Duration deadline;
    private final Consumer<String> log;

    public QkdPadMaterialFetcher(Qkd014Client qkdClient) {
        this(qkdClient, duration -> Thread.sleep(duration.toMillis()), DEFAULT_POLL, DEFAULT_DEADLINE, LOG::info);
    }

    /** Same defaults as {@link #QkdPadMaterialFetcher(Qkd014Client)} with a custom progress sink. */
    public QkdPadMaterialFetcher(Qkd014Client qkdClient, Consumer<String> log) {
        this(qkdClient, duration -> Thread.sleep(duration.toMillis()), DEFAULT_POLL, DEFAULT_DEADLINE, log);
    }

    QkdPadMaterialFetcher(
            Qkd014Client qkdClient,
            Sleeper sleeper,
            Duration poll,
            Duration deadline,
            Consumer<String> log
    ) {
        this.qkdClient = Objects.requireNonNull(qkdClient, "qkdClient must not be null");
        this.sleeper = Objects.requireNonNull(sleeper, "sleeper must not be null");
        this.poll = Objects.requireNonNull(poll, "poll must not be null");
        this.deadline = Objects.requireNonNull(deadline, "deadline must not be null");
        this.log = Objects.requireNonNull(log, "log must not be null");
    }

    public FetchedKeys fetch(String slaveSaeId, SeSessionUplink uplink) throws Qkd014ClientException {
        int plainMax = uplink.plainMax();
        int targetPads = uplink.maxPadsForBudget();
        if (targetPads <= 0) {
            throw new IllegalStateException("Uplink geometry yields zero pad slots");
        }
        int targetBytes = targetPads * plainMax;
        Instant waitDeadline = null;
        boolean pack = true;

        List<String> keyIds = new ArrayList<>();
        List<String> keyMaterial = new ArrayList<>();

        KmeStatus status = qkdClient.getStatus(slaveSaeId);
        int stored = storedCount(status);
        logStatus(slaveSaeId, status, stored, 0, targetBytes, targetPads, plainMax, pack);

        while (SeBytes.decodedBase64ByteLength(keyMaterial) < targetBytes) {
            int poolBits = status.keySizeBits();
            int packedBits = packedKeySizeBits(status.maxKeySizeBits(), poolBits);
            int maxPerRequest = status.maxKeysPerRequest();
            int haveBytes = SeBytes.decodedBase64ByteLength(keyMaterial);
            int remainingBytes = targetBytes - haveBytes;
            int remainingBits = remainingBytes * 8;
            int storedBits = stored * poolBits;

            int sizeBits;
            int number;
            int unitsPerKey;
            if (pack && storedBits >= packedBits) {
                sizeBits = packedBits;
                unitsPerKey = packedBits / poolBits;
                int maxPacked = stored / unitsPerKey;
                int keysNeeded = (remainingBytes + bitsToBytes(sizeBits) - 1) / bitsToBytes(sizeBits);
                number = Math.max(1, Math.min(keysNeeded, Math.min(maxPerRequest, maxPacked)));
            } else if (stored > 0 && storedBits >= remainingBits) {
                sizeBits = poolBits;
                unitsPerKey = 1;
                int keysNeeded = (remainingBytes + bitsToBytes(sizeBits) - 1) / bitsToBytes(sizeBits);
                number = Math.max(1, Math.min(keysNeeded, Math.min(maxPerRequest, stored)));
            } else if (!pack && stored > 0 && storedBits >= poolBits) {
                sizeBits = poolBits;
                unitsPerKey = 1;
                int keysNeeded = (remainingBytes + bitsToBytes(sizeBits) - 1) / bitsToBytes(sizeBits);
                number = Math.max(1, Math.min(keysNeeded, Math.min(maxPerRequest, stored)));
            } else {
                Instant next = waitOrAcceptPartial(
                        waitDeadline,
                        slaveSaeId,
                        stored <= 0 ? "pool empty" : "leftover " + stored + " × " + poolBits + " bits",
                        keyMaterial,
                        plainMax,
                        targetBytes,
                        targetPads);
                if (next == null) {
                    break;
                }
                waitDeadline = next;
                status = qkdClient.getStatus(slaveSaeId);
                stored = storedCount(status);
                logStatus(slaveSaeId, status, stored, haveBytes, targetBytes, targetPads, plainMax, pack);
                continue;
            }

            KeyContainer batch;
            try {
                logGetKey(haveBytes, targetBytes, targetPads, plainMax, number);
                batch = qkdClient.getKey(slaveSaeId, number, sizeBits);
            } catch (Qkd014ClientException ex) {
                if (pack && keyTooLarge(ex)) {
                    pack = false;
                    log.accept("Retrying with smaller key batches…");
                    continue;
                }
                if (!insufficientMaterial(ex)) {
                    throw ex;
                }
                status = qkdClient.getStatus(slaveSaeId);
                stored = storedCount(status);
                logStatus(slaveSaeId, status, stored, haveBytes, targetBytes, targetPads, plainMax, pack);
                Instant next = waitOrAcceptPartial(waitDeadline, slaveSaeId, ex.getMessage(),
                        keyMaterial, plainMax, targetBytes, targetPads);
                if (next == null) {
                    break;
                }
                waitDeadline = next;
                continue;
            }

            int before = keyIds.size();
            accumulate(batch, keyIds, keyMaterial);
            int got = keyIds.size() - before;
            if (got == 0) {
                Instant next = waitOrAcceptPartial(waitDeadline, slaveSaeId, "empty key container",
                        keyMaterial, plainMax, targetBytes, targetPads);
                if (next == null) {
                    break;
                }
                waitDeadline = next;
                continue;
            }
            stored = Math.max(0, stored - got * unitsPerKey);
        }

        int haveBytes = SeBytes.decodedBase64ByteLength(keyMaterial);
        int havePads = haveBytes / plainMax;
        if (havePads < MIN_PARTIAL_PADS && haveBytes < targetBytes) {
            throw new Qkd014ClientException(
                    "KME pool for " + slaveSaeId + " yielded only " + havePads
                            + " pads (" + haveBytes + " bytes, need " + targetBytes + ")",
                    400,
                    null);
        }
        logDone(havePads, targetPads);
        return new FetchedKeys(keyIds, keyMaterial);
    }

    /**
     * Request {@code size} taken from status {@code max_key_size}, snapped down to a
     * multiple of the pool unit so {@code stored_key_count} consumption is exact.
     */
    static int packedKeySizeBits(int maxKeySizeBits, int poolBits) {
        int alignedMax = maxKeySizeBits - (maxKeySizeBits % 8);
        if (poolBits >= 8) {
            int size = alignedMax - (alignedMax % poolBits);
            return Math.max(poolBits, size);
        }
        return Math.max(8, alignedMax);
    }

    /** {@code null} means keep the partial fetch; otherwise the replenishment deadline. */
    private Instant waitOrAcceptPartial(
            Instant waitDeadline,
            String slaveSaeId,
            String reason,
            List<String> keyMaterial,
            int plainMax,
            int targetBytes,
            int targetPads
    ) throws Qkd014ClientException {
        Instant giveUp = waitDeadline == null ? Instant.now().plus(deadline) : waitDeadline;
        Duration remaining = Duration.between(Instant.now(), giveUp);
        if (remaining.isNegative() || remaining.isZero()) {
            int haveBytes = SeBytes.decodedBase64ByteLength(keyMaterial);
            int havePads = haveBytes / plainMax;
            if (havePads >= MIN_PARTIAL_PADS) {
                logPartial(havePads, targetPads);
                return null;
            }
            throw new Qkd014ClientException(
                    "KME pool for " + slaveSaeId + " did not replenish in " + deadline.toSeconds()
                            + "s (" + reason + ")",
                    400,
                    null);
        }
        Duration nap = remaining.compareTo(poll) < 0 ? remaining : poll;
        log.accept("Waiting for more keys in the pool…");
        try {
            sleeper.sleep(nap);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new Qkd014ClientException("QKD fetch interrupted while waiting for KME replenishment", e);
        }
        return giveUp;
    }

    private void logStatus(
            String slaveSaeId,
            KmeStatus status,
            int stored,
            int haveBytes,
            int targetBytes,
            int targetPads,
            int plainMax,
            boolean pack
    ) {
        int havePads = plainMax > 0 ? haveBytes / plainMax : 0;
        if (havePads <= 0) {
            log.accept("Fetching keys from quantum network (0 of " + targetPads + " pads)…");
        } else {
            logProgress(havePads, targetPads);
        }
    }

    private void logProgress(int havePads, int targetPads) {
        log.accept("Keys in progress: " + havePads + " of " + targetPads + " pads ready.");
    }

    private void logGetKey(int haveBytes, int targetBytes, int targetPads, int plainMax, int batchCount) {
        int havePads = plainMax > 0 ? haveBytes / plainMax : 0;
        if (havePads <= 0) {
            log.accept("Requesting keys from quantum network…");
        } else {
            log.accept("Requesting more keys (" + havePads + " of " + targetPads + " pads ready)…");
        }
    }

    private void logPartial(int havePads, int targetPads) {
        log.accept("Continuing with " + havePads + " of " + targetPads
                + " pads — the pool did not fill in time.");
    }

    private void logDone(int havePads, int targetPads) {
        if (havePads >= targetPads) {
            log.accept("Keys ready: " + havePads + " pads prepared.");
        } else {
            log.accept("Keys ready: " + havePads + " of " + targetPads + " pads prepared.");
        }
    }

    private static int storedCount(KmeStatus status) {
        if (status.stored_key_count == null) {
            return status.maxKeysPerRequest();
        }
        return Math.max(0, status.stored_key_count);
    }

    private static boolean insufficientMaterial(Qkd014ClientException ex) {
        String message = ex.getMessage();
        return message != null
                && message.toLowerCase(Locale.ROOT).contains("not enough key material");
    }

    private static boolean keyTooLarge(Qkd014ClientException ex) {
        if (ex.getHttpStatusCode() == 500) {
            return true;
        }
        String message = ex.getMessage();
        if (message == null) {
            return false;
        }
        String lower = message.toLowerCase(Locale.ROOT);
        return lower.contains("value too long") || lower.contains("character varying");
    }

    private static int bitsToBytes(int sizeBits) {
        return Math.max(1, sizeBits / 8);
    }

    private static void accumulate(KeyContainer container, List<String> keyIds, List<String> keyMaterial) {
        List<KeyItem> keys = KeyItems.extractKeys(container);
        keyIds.addAll(KeyItems.extractKeyIds(keys));
        keyMaterial.addAll(KeyItems.extractKeyMaterial(keys));
    }
}
