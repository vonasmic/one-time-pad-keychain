package fel.cvut.se;

import org.bouncycastle.jsse.BCSSLSocket;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Typed SE TLS session uplink (LV version 4), after binding verification.
 */
public record SeSessionUplink(
        byte[] clientHash,
        int slotSize,
        int padCount,
        byte[] fillId,
        byte[] mlkemPublicKey,
        List<PeerEntry> peers
) {
    public record PeerEntry(byte[] hash, String nickname) {
        public PeerEntry {
            Objects.requireNonNull(hash, "hash must not be null");
            if (hash.length != SeConstants.PEER_HASH_LEN) {
                throw new IllegalArgumentException("peer hash must be " + SeConstants.PEER_HASH_LEN + " bytes");
            }
            nickname = nickname == null ? "" : nickname;
        }

        public String hashHex() {
            return SeBytes.toHex(hash);
        }
    }

    public SeSessionUplink {
        Objects.requireNonNull(clientHash, "clientHash must not be null");
        Objects.requireNonNull(fillId, "fillId must not be null");
        Objects.requireNonNull(mlkemPublicKey, "mlkemPublicKey must not be null");
        Objects.requireNonNull(peers, "peers must not be null");
        if (clientHash.length != SeConstants.CLIENT_HASH_LEN) {
            throw new IllegalArgumentException("clientHash length");
        }
        if (fillId.length != SeConstants.FILL_ID_LEN) {
            throw new IllegalArgumentException("fillId length");
        }
        if (mlkemPublicKey.length != SeConstants.MLKEM_PK_LEN) {
            throw new IllegalArgumentException("mlkemPublicKey length");
        }
        if (slotSize <= SeConstants.RMEM_OVERHEAD) {
            throw new IllegalArgumentException("slotSize too small: " + slotSize);
        }
        if (padCount <= 0) {
            throw new IllegalArgumentException("padCount must be positive: " + padCount);
        }
        peers = List.copyOf(peers);
    }

    public String clientHashHex() {
        return SeBytes.toHex(clientHash);
    }

    /** Plaintext ceiling for one pad slot ({@code slotSize - AEAD overhead}). */
    public int plainMax() {
        return slotSize - SeConstants.RMEM_OVERHEAD;
    }

    /**
     * Max pad slots under {@link SeConstants#QKD_MAX_BYTES}. Ingest counts {@code kem_ct}
     * and the 1-byte {@code decrypt_half} item toward that cap.
     */
    public int maxPadsForBudget() {
        int budgetPads = (SeConstants.QKD_MAX_BYTES
                - SeConstants.MLKEM_CT_LEN
                - SeConstants.DECRYPT_HALF_LEN) / slotSize;
        return Math.max(0, Math.min(padCount, budgetPads));
    }

    public static SeSessionUplink readAndVerify(SSLSocket socket, byte[] exporter) throws IOException {
        Objects.requireNonNull(socket, "socket must not be null");
        Objects.requireNonNull(exporter, "exporter must not be null");
        var session = ((BCSSLSocket) socket).getBCSession();
        return readAndVerify(
                socket.getInputStream(),
                exporter,
                SeSessionBinding.peerTlsSpki(session)
        );
    }

    public static SeSessionUplink readAndVerify(InputStream in, byte[] exporter, byte[] peerTlsSpki)
            throws IOException {
        Objects.requireNonNull(in, "in must not be null");
        SecureLv.Envelope envelope = SecureLv.readFrom(in);
        if (envelope.version() != SeConstants.LV_UPLINK_VERSION) {
            throw new IOException("Uplink schema mismatch: got v" + envelope.version()
                    + ", expect v" + SeConstants.LV_UPLINK_VERSION);
        }

        List<byte[]> items = envelope.items();
        if (items.size() < SeConstants.LV_UPLINK_FIXED_ITEMS) {
            throw new IOException("Uplink too few items: " + items.size());
        }
        int peerPairCount = items.size() - SeConstants.LV_UPLINK_FIXED_ITEMS;
        if ((peerPairCount & 1) != 0) {
            throw new IOException("Uplink peer items must come in hash/name pairs");
        }

        byte[] sessionSig = SeBytes.requireLen(items.get(0), SeConstants.SESSION_SIG_LEN, "session signature");
        byte[] eccPub = SeBytes.requireLen(items.get(1), SeConstants.ECC_PUB_LEN, "ecc public key");
        byte[] clientHash = SeBytes.requireLen(items.get(2), SeConstants.CLIENT_HASH_LEN, "client hash");
        int slotSize = SeBytes.readU16Le(items.get(3), "slot size");
        int padCount = SeBytes.readU16Le(items.get(4), "pad count");
        byte[] fillId = SeBytes.requireLen(items.get(5), SeConstants.FILL_ID_LEN, "fill_id");
        byte[] mlkemPublicKey = SeBytes.requireLen(items.get(6), SeConstants.MLKEM_PK_LEN, "ML-KEM public key");

        SeSessionBinding.verify(peerTlsSpki, exporter, eccPub, clientHash, sessionSig);

        List<PeerEntry> peers = new ArrayList<>(peerPairCount / 2);
        for (int i = SeConstants.LV_UPLINK_FIXED_ITEMS; i < items.size(); i += 2) {
            byte[] hash = SeBytes.requireLen(items.get(i), SeConstants.PEER_HASH_LEN, "peer hash");
            String name = new String(items.get(i + 1), StandardCharsets.UTF_8);
            peers.add(new PeerEntry(hash, name));
        }
        return new SeSessionUplink(clientHash, slotSize, padCount, fillId, mlkemPublicKey, peers);
    }
}
