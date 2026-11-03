package fel.cvut.integration.node;

import fel.cvut.harness.ProvisionCluster;
import fel.cvut.harness.ProvisionCluster.SaeNode;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.pairlock.PairLockRegistry;
import fel.cvut.node.pairlock.PairOperation;
import fel.cvut.node.recordManager.ClientRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.List;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Key material of a pair is stored once and only by the lease holder; a new share replaces it. */
@Tag("integration")
@Timeout(60)
class KeystreamOnceTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private ProvisionCluster cluster;
    private SaeNode origin;
    private SaeNode peer;
    private SaeNode other;

    @BeforeEach
    void setUp() throws Exception {
        cluster = new ProvisionCluster(SQLITE);
        origin = cluster.origin();
        peer = cluster.peerA();
        other = cluster.peerB();
    }

    @AfterEach
    void tearDown() {
        cluster.close();
    }

    @Test
    void sameIssuerReplacesItsShareOnThePeerAndDropsTheOldKeys() throws Exception {
        share(origin);
        byte[] first = peerCiphertext();
        share(origin);
        assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
        assertFalse(Arrays.equals(first, peerCiphertext()), "the new share has new key material");
        assertEquals(origin.row(HASH_1, HASH_2).orElseThrow().token(), peer.row(HASH_2, HASH_1).orElseThrow().token());
    }

    @Test
    void secondSaeCannotLockOrWriteWhileTheIssuerHoldsThePair() throws Exception {
        share(origin);
        byte[] ciphertext = peerCiphertext();
        try (PairOperation held = origin.locks.acquire(origin.id(), peer.id(), HASH_1, HASH_2)) {
            NodeCommands peerAsOther = other.rmi.connectBySaeId(peer.id());
            String token = PairLockRegistry.newToken();
            assertFalse(peerAsOther.lockPair(HASH_2, HASH_1, token));
            ClientRecord record = SaeFixtures.record(HASH_2, HASH_1, other.id(), List.of("key-1"));
            assertThrows(PairLockLostException.class, () -> peerAsOther.insert(record, token));
            assertThrows(PairLockLostException.class, () -> peerAsOther.insert(record, held.token()),
                    "another SAE cannot use the issuer's token");
        }
        assertArrayEquals(ciphertext, peerCiphertext());
        assertEquals(origin.id(), peer.row(HASH_2, HASH_1).orElseThrow().saeId());
    }

    @Test
    void anotherSaeReplacesTheShareOnlyUnderBothLocks() throws Exception {
        share(origin);
        byte[] first = peerCiphertext();
        share(other);
        assertFalse(Arrays.equals(first, peerCiphertext()));
        assertEquals(other.id(), peer.row(HASH_2, HASH_1).orElseThrow().saeId());
        assertEquals(1, SaeFixtures.countKeyMaterial(SQLITE.peer()));
        // The stale origin row no longer matches the peer's token: an orphan, never delivered.
        assertFalse(origin.row(HASH_1, HASH_2).orElseThrow().token()
                .equals(peer.row(HASH_2, HASH_1).orElseThrow().token()));
    }

    private void share(SaeNode issuer) throws Exception {
        ClientRecord record = SaeFixtures.record(HASH_1, HASH_2, peer.id(), List.of());
        try (PairOperation operation = issuer.locks.acquire(issuer.id(), peer.id(), HASH_1, HASH_2)) {
            ProvisionSession.Exchange.Prepared prepared = issuer.sync().prepare(record, SaeFixtures.uplink());
            operation.checkpoint();
            issuer.sync().insertPeer(record.withPayload(prepared.keyIds()), operation.token());
            issuer.sync().writeOrigin(record.withPayload(prepared.keyIds()), operation.token());
        }
    }

    private static byte[] peerCiphertext() throws Exception {
        try (Connection connection = SQLITE.peer().getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT ciphertext FROM shared_key_material WHERE client_hash1 = ? AND client_hash2 = ?")) {
            statement.setString(1, HASH_2);
            statement.setString(2, HASH_1);
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                return resultSet.getBytes(1);
            }
        }
    }
}
