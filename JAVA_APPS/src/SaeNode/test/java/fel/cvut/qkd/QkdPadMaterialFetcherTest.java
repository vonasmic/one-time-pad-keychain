package fel.cvut.qkd;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeSessionUplink;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class QkdPadMaterialFetcherTest {

    private static final int POOL_BITS = 512;
    private static final int POOL_BYTES = POOL_BITS / 8;
    private static final int MAX_KEY_BITS = 100_000;
    private static final int PACKED_BITS = QkdPadMaterialFetcher.packedKeySizeBits(MAX_KEY_BITS, POOL_BITS);
    private static final int PACKED_BYTES = PACKED_BITS / 8;

    @Test
    void packedSizeIsStatusMaxKeySizeAlignedToPoolUnit() {
        assertEquals(99_840, PACKED_BITS);
        assertEquals(0, PACKED_BITS % POOL_BITS);
        assertEquals(4_096, QkdPadMaterialFetcher.packedKeySizeBits(4_096, POOL_BITS));
        assertEquals(POOL_BITS, QkdPadMaterialFetcher.packedKeySizeBits(POOL_BITS, POOL_BITS));
    }

    @Test
    void fetchPacksOneLargeKeyWhenPoolCoversIt() throws Exception {
        SeSessionUplink uplink = padUplink(3);
        int targetBytes = uplink.maxPadsForBudget() * uplink.plainMax();
        Qkd014Client qkd = mock(Qkd014Client.class);
        when(qkd.getStatus("sae-2")).thenReturn(status(100, POOL_BITS, 1953, MAX_KEY_BITS));
        when(qkd.getKey(eq("sae-2"), any(), eq(PACKED_BITS))).thenAnswer(invocation -> {
            int number = invocation.getArgument(1);
            assertEquals(1, number);
            return keys(number, PACKED_BYTES);
        });

        QkdPadMaterialFetcher.FetchedKeys fetched = fetcher(qkd).fetch("sae-2", uplink);

        assertTrue(SeBytes.decodedBase64ByteLength(fetched.keyMaterial()) >= targetBytes);
        assertEquals(1, fetched.keyIds().size());
        verify(qkd, times(1)).getStatus("sae-2");
        verify(qkd, times(1)).getKey("sae-2", 1, PACKED_BITS);
        verify(qkd, never()).getKey(any(), any(), eq(POOL_BITS));
        verify(qkd, never()).getKey(any(), any(), eq(MAX_KEY_BITS));
        verify(qkd, never()).getKey(any(), any(), isNull());
    }

    @Test
    void fetchUsesMaxKeySizeFromStatus() throws Exception {
        int statusMax = 4_096;
        int packed = QkdPadMaterialFetcher.packedKeySizeBits(statusMax, POOL_BITS);
        SeSessionUplink uplink = padUplink(3);
        Qkd014Client qkd = mock(Qkd014Client.class);
        when(qkd.getStatus("sae-2")).thenReturn(status(100, POOL_BITS, 1953, statusMax));
        when(qkd.getKey(eq("sae-2"), any(), eq(packed))).thenAnswer(invocation ->
                keys(invocation.getArgument(1), packed / 8));

        fetcher(qkd).fetch("sae-2", uplink);

        verify(qkd).getKey(eq("sae-2"), any(), eq(packed));
        verify(qkd, never()).getKey(any(), any(), eq(MAX_KEY_BITS));
        verify(qkd, never()).getKey(any(), any(), eq(PACKED_BITS));
    }

    @Test
    void fetchDoesNotRequestMorePackedKeysThanThePoolHolds() throws Exception {
        SeSessionUplink uplink = padUplink(507);
        int unitsPerKey = PACKED_BITS / POOL_BITS;
        int maxPacked = 1953 / unitsPerKey;
        Qkd014Client qkd = mock(Qkd014Client.class);
        when(qkd.getStatus("sae-2"))
                .thenReturn(status(100, POOL_BITS, 1953, MAX_KEY_BITS))
                .thenReturn(status(100, POOL_BITS, 1953, MAX_KEY_BITS));
        when(qkd.getKey(eq("sae-2"), any(), eq(PACKED_BITS))).thenAnswer(invocation -> {
            int number = invocation.getArgument(1);
            assertTrue(number <= maxPacked);
            assertTrue(number <= 100);
            return keys(number, PACKED_BYTES);
        });

        fetcher(qkd).fetch("sae-2", uplink);

        verify(qkd, atLeast(1)).getKey(eq("sae-2"), eq(maxPacked), eq(PACKED_BITS));
        verify(qkd, never()).getKey(any(), any(), eq(MAX_KEY_BITS));
        verify(qkd, never()).getKey(any(), any(), eq(POOL_BITS));
    }

    @Test
    void http500OnPackedSizeFallsBackToKeySize() throws Exception {
        SeSessionUplink uplink = padUplink(3);
        Qkd014Client qkd = mock(Qkd014Client.class);
        when(qkd.getStatus("sae-2")).thenReturn(status(100, POOL_BITS, 1953, MAX_KEY_BITS));
        AtomicInteger packedTries = new AtomicInteger();
        when(qkd.getKey(eq("sae-2"), any(), eq(PACKED_BITS))).thenAnswer(invocation -> {
            packedTries.incrementAndGet();
            throw new Qkd014ClientException("value too long for type character varying(16664)", 500, null);
        });
        when(qkd.getKey(eq("sae-2"), any(), eq(POOL_BITS))).thenAnswer(invocation ->
                keys(invocation.getArgument(1), POOL_BYTES));

        fetcher(qkd).fetch("sae-2", uplink);

        assertEquals(1, packedTries.get());
        verify(qkd, atLeast(1)).getKey(eq("sae-2"), any(), eq(POOL_BITS));
    }

    @Test
    void insufficientMaterialRefreshesStatus() throws Exception {
        SeSessionUplink uplink = padUplink(3);
        Qkd014Client qkd = mock(Qkd014Client.class);
        when(qkd.getStatus("sae-2"))
                .thenReturn(status(100, POOL_BITS, 1953, MAX_KEY_BITS))
                .thenReturn(status(100, POOL_BITS, 200, MAX_KEY_BITS));
        AtomicInteger requests = new AtomicInteger();
        AtomicInteger secondBatch = new AtomicInteger();
        when(qkd.getKey(eq("sae-2"), any(), eq(PACKED_BITS))).thenAnswer(invocation -> {
            int number = invocation.getArgument(1);
            int n = requests.incrementAndGet();
            if (n == 1) {
                throw new Qkd014ClientException("Not enough key material available", 400, null);
            }
            secondBatch.set(number);
            return keys(number, PACKED_BYTES);
        });

        fetcher(qkd).fetch("sae-2", uplink);

        assertEquals(1, secondBatch.get());
    }

    @Test
    void waitsWhenPoolIsEmptyThenContinues() throws Exception {
        SeSessionUplink uplink = padUplink(3);
        Qkd014Client qkd = mock(Qkd014Client.class);
        when(qkd.getStatus("sae-2"))
                .thenReturn(status(100, POOL_BITS, 0, MAX_KEY_BITS))
                .thenReturn(status(100, POOL_BITS, 1000, MAX_KEY_BITS));
        when(qkd.getKey(eq("sae-2"), any(), eq(PACKED_BITS))).thenAnswer(invocation ->
                keys(invocation.getArgument(1), PACKED_BYTES));
        AtomicInteger waits = new AtomicInteger();

        fetcher(qkd, duration -> waits.incrementAndGet()).fetch("sae-2", uplink);

        assertEquals(1, waits.get());
        verify(qkd, atLeast(1)).getKey(eq("sae-2"), any(), eq(PACKED_BITS));
    }

    @Test
    void keepsPartialFetchWhenPoolDoesNotReplenish() throws Exception {
        SeSessionUplink uplink = padUplink(507);
        Qkd014Client qkd = mock(Qkd014Client.class);
        when(qkd.getStatus("sae-2")).thenReturn(status(100, POOL_BITS, 195, MAX_KEY_BITS));
        when(qkd.getKey(eq("sae-2"), any(), eq(PACKED_BITS))).thenAnswer(invocation ->
                keys(invocation.getArgument(1), PACKED_BYTES));

        QkdPadMaterialFetcher.FetchedKeys fetched =
                new QkdPadMaterialFetcher(qkd, duration -> { }, Duration.ZERO, Duration.ZERO, message -> { })
                        .fetch("sae-2", uplink);

        int havePads = SeBytes.decodedBase64ByteLength(fetched.keyMaterial()) / uplink.plainMax();
        assertTrue(havePads >= QkdPadMaterialFetcher.MIN_PARTIAL_PADS);
        assertTrue(havePads < uplink.maxPadsForBudget());
        verify(qkd, times(1)).getKey(eq("sae-2"), eq(1), eq(PACKED_BITS));
    }

    @Test
    void finishesWithPoolUnitsWhenTheyCoverTheRemainder() throws Exception {
        SeSessionUplink uplink = padUplink(3);
        Qkd014Client qkd = mock(Qkd014Client.class);
        when(qkd.getStatus("sae-2")).thenReturn(status(100, POOL_BITS, 30, MAX_KEY_BITS));
        when(qkd.getKey(eq("sae-2"), any(), eq(POOL_BITS))).thenAnswer(invocation ->
                keys(invocation.getArgument(1), POOL_BYTES));

        fetcher(qkd).fetch("sae-2", uplink);

        verify(qkd, times(1)).getKey(eq("sae-2"), any(), eq(POOL_BITS));
        verify(qkd, never()).getKey(any(), any(), eq(PACKED_BITS));
    }

    @Test
    void kmeFailurePropagatesWhenNoMaterialIsFetched() throws Exception {
        SeSessionUplink uplink = padUplink(3);
        Qkd014Client qkd = mock(Qkd014Client.class);
        when(qkd.getStatus(any())).thenReturn(status(8, POOL_BITS, 10_000, MAX_KEY_BITS));
        when(qkd.getKey(any(), any(), eq(PACKED_BITS)))
                .thenThrow(new Qkd014ClientException("kme down", 503, null));

        assertThrows(Qkd014ClientException.class, () -> fetcher(qkd).fetch("sae-2", uplink));
        verify(qkd, times(1)).getKey(any(), any(), eq(PACKED_BITS));
    }

    @Test
    void fixtureUplinkHasRoomForAtLeastOnePad() {
        SeSessionUplink uplink = fel.cvut.harness.SaeFixtures.uplink();
        assertTrue(uplink.maxPadsForBudget() >= 1);
        assertEquals(uplink.slotSize() - SeConstants.RMEM_OVERHEAD, uplink.plainMax());
    }

    private static QkdPadMaterialFetcher fetcher(Qkd014Client qkd) {
        return fetcher(qkd, duration -> { });
    }

    private static QkdPadMaterialFetcher fetcher(Qkd014Client qkd, QkdPadMaterialFetcher.Sleeper sleeper) {
        return new QkdPadMaterialFetcher(qkd, sleeper, Duration.ZERO, Duration.ofMinutes(5), message -> { });
    }

    private static KmeStatus status(int maxPerRequest, int keySizeBits, int stored, int maxKeySizeBits) {
        KmeStatus status = new KmeStatus();
        status.max_key_size = maxKeySizeBits;
        status.max_key_per_request = maxPerRequest;
        status.key_size = keySizeBits;
        status.stored_key_count = stored;
        return status;
    }

    private static KeyContainer keys(int number, int keyBytes) {
        List<KeyItem> keys = new ArrayList<>(number);
        for (int i = 0; i < number; i++) {
            KeyItem item = new KeyItem();
            item.key_ID = "key-" + i;
            item.key = Base64.getEncoder().encodeToString(new byte[keyBytes]);
            keys.add(item);
        }
        KeyContainer container = new KeyContainer();
        container.keys = keys;
        return container;
    }

    private static SeSessionUplink padUplink(int padCount) {
        return new SeSessionUplink(
                new byte[SeConstants.CLIENT_HASH_LEN],
                SeConstants.RMEM_SLOT_MAX,
                padCount,
                new byte[SeConstants.FILL_ID_LEN],
                new byte[SeConstants.MLKEM_PK_LEN],
                List.of(new SeSessionUplink.PeerEntry(new byte[SeConstants.PEER_HASH_LEN], "peer"))
        );
    }
}
