package fel.cvut.harness;

import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.db.ClientRecordStateRepository;
import fel.cvut.db.RecordRetention;
import fel.cvut.db.SharedKeyMaterialRepository;
import fel.cvut.node.Address;
import fel.cvut.node.NodeRef;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.KeyItem;
import fel.cvut.qkd.KmeStatus;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeSessionUplink;
import fel.cvut.utimaco.HsmAesGcm;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class SaeFixtures {

    public static final String ORIGIN_SAE = "sae-1";
    public static final String PEER_SAE = "sae-2";
    public static final String OTHER_SAE = "sae-3";
    public static final String HASH_1 = "a".repeat(64);
    public static final String HASH_2 = "b".repeat(64);
    public static final int UPLINK_SLOT = 64;

    private SaeFixtures() {
    }

    public static NodeRef originRef() {
        return new NodeRef(new Address("127.0.0.1", 2010), ORIGIN_SAE);
    }

    public static NodeRef peerRef() {
        return new NodeRef(new Address("127.0.0.1", 2020), PEER_SAE);
    }

    public static NodeRef otherRef() {
        return new NodeRef(new Address("127.0.0.1", 2030), OTHER_SAE);
    }

    public static AtomicRecordStateMap stateMap(String saeId, DataSource dataSource) {
        return new AtomicRecordStateMap(
                saeId,
                dataSource,
                new ClientRecordStateRepository(),
                Duration.ofDays(RecordRetention.DEFAULT_RETENTION_DAYS)
        );
    }

    public static SharedKeyMaterialStore keyStore(DataSource dataSource, HsmAesGcm hsmAesGcm) {
        return new SharedKeyMaterialStore(
                dataSource,
                new SharedKeyMaterialRepository(),
                new ClientRecordStateRepository(),
                hsmAesGcm,
                new ObjectMapper(),
                Duration.ofDays(RecordRetention.DEFAULT_RETENTION_DAYS)
        );
    }

    public static NodeCommandsService commands(
            NodeRef selfRef,
            DataSource dataSource,
            Qkd014Client qkdClient,
            HsmAesGcm hsmAesGcm
    ) {
        return new NodeCommandsService(
                selfRef,
                stateMap(selfRef.getNodeId(), dataSource),
                qkdClient,
                keyStore(dataSource, hsmAesGcm)
        );
    }

    public static int padPlain() {
        return UPLINK_SLOT - SeConstants.RMEM_OVERHEAD;
    }

    public static ClientRecord record(String hash1, String hash2, String targetSaeId, List<String> payload) {
        return new ClientRecord(hash1, hash2, payload, targetSaeId, padPlain());
    }

    public static ClientRecord.ClientHeader header(String hash1, String hash2, String targetSaeId) {
        return new ClientRecord.ClientHeader(hash1, hash2, targetSaeId, padPlain());
    }

    public static SeSessionUplink.PeerEntry peer(String nickname) {
        return new SeSessionUplink.PeerEntry(new byte[SeConstants.PEER_HASH_LEN], nickname, padPlain());
    }

    public static SeSessionUplink uplink() {
        return new SeSessionUplink(
                new byte[SeConstants.CLIENT_HASH_LEN],
                UPLINK_SLOT,
                1,
                new byte[SeConstants.FILL_ID_LEN],
                new byte[SeConstants.MLKEM_PK_LEN],
                List.of(peer("peer"))
        );
    }

    public static KeyContainer keyContainer(String keyId, int payloadBytes) {
        KeyItem item = new KeyItem();
        item.key_ID = keyId;
        item.key = Base64.getEncoder().encodeToString(new byte[payloadBytes]);
        KeyContainer container = new KeyContainer();
        container.keys = List.of(item);
        return container;
    }

    public static long countRecords(DataSource dataSource) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.createStatement();
             var resultSet = statement.executeQuery("SELECT COUNT(*) FROM client_record_state")) {
            resultSet.next();
            return resultSet.getLong(1);
        }
    }

    public static long countKeyMaterial(DataSource dataSource) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.createStatement();
             var resultSet = statement.executeQuery("SELECT COUNT(*) FROM shared_key_material")) {
            resultSet.next();
            return resultSet.getLong(1);
        }
    }

    public static Qkd014Client mockQkd() {
        SeSessionUplink uplink = uplink();
        int payloadBytes = Math.max(64, uplink.plainMax() * uplink.padCount());
        return mockQkdWithKey("key-1", Base64.getEncoder().encodeToString(new byte[payloadBytes]));
    }

    public static Qkd014Client mockQkdWithKey(String keyId, String keyMaterial) {
        Qkd014Client qkd = mock(Qkd014Client.class);
        KeyItem item = new KeyItem();
        item.key_ID = keyId;
        item.key = keyMaterial;
        KeyContainer keys = new KeyContainer();
        keys.keys = List.of(item);
        try {
            KmeStatus status = new KmeStatus();
            status.max_key_size = Math.max(64, keyMaterial.length()) * 8;
            status.max_key_per_request = 1;
            when(qkd.getStatus(any())).thenReturn(status);
            when(qkd.getKey(any(), any(), nullable(Integer.class))).thenReturn(keys);
            when(qkd.getKeyWithKeyIds(any(), anyList())).thenReturn(keys);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to stub Qkd014Client", ex);
        }
        return qkd;
    }
}
