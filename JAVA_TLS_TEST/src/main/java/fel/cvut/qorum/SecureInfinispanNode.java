package fel.cvut.qorum;

import fel.cvut.qorum.marshall.QorumSerializationContextImpl;
import org.infinispan.Cache;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.transaction.LockingMode;
import org.infinispan.transaction.TransactionMode;
import jakarta.transaction.TransactionManager;

public class SecureInfinispanNode implements AutoCloseable {
    private final DefaultCacheManager cacheManager;
    private final Cache<RecordKey, RecordPayload> cache;
    private final TransactionManager tm;
    private final String myNodeId;

    public SecureInfinispanNode(String myNodeId) {
        this.myNodeId = myNodeId;

        int bindPort = Integer.getInteger("jgroups.bind.port", JGroupsPqcStack.defaultPortFor(myNodeId));

        GlobalConfigurationBuilder global = GlobalConfigurationBuilder.defaultClusteredBuilder();
        global.serialization().addContextInitializer(new QorumSerializationContextImpl());
        global.transport()
                .clusterName("Secure-PQC-Cluster")
                .nodeName(myNodeId)
                .stack("pqc")
                .jgroups()
                .addStack("pqc")
                .channelConfigurator(JGroupsPqcStack.createConfigurator("pqc", bindPort, myNodeId));

        ConfigurationBuilder config = new ConfigurationBuilder();
        config.clustering().cacheMode(org.infinispan.configuration.cache.CacheMode.REPL_SYNC)
                .transaction()
                .transactionMode(TransactionMode.TRANSACTIONAL)
                .lockingMode(LockingMode.PESSIMISTIC)
                .locking()
                .lockAcquisitionTimeout(10000);

        this.cacheManager = new DefaultCacheManager(global.build());
        this.cacheManager.defineConfiguration("secure-map", config.build());
        this.cache = this.cacheManager.getCache("secure-map");

        this.tm = cache.getAdvancedCache().getTransactionManager();
    }

    /**
     * LOCK -> WRITE -> UNLOCK (via commit)
     */
    public void secureWrite(ClientRecord record) throws Exception {
        RecordKey key = record.createKey();
        RecordPayload payload = record.createPayload();

        tm.begin();
        try {
            cache.getAdvancedCache().lock(key);
            cache.put(key, payload);
            tm.commit();
            System.out.println("Write successful and locked released.");

        } catch (Exception e) {
            if (tm.getStatus() == jakarta.transaction.Status.STATUS_ACTIVE) {
                tm.rollback();
            }
            throw new Exception("Write failed, lock rolled back.", e);
        }
    }

    /**
     * LOCK -> READ -> UNLOCK (via commit)
     */
    public String secureRead(RecordKey key) throws Exception {
        tm.begin();
        try {
            cache.getAdvancedCache().lock(key);

            RecordPayload payload = cache.get(key);

            if (payload == null) {
                tm.commit();
                return null;
            }

            String expectedData = key.toString() + payload.jsonValue;
            boolean isValid = PqcCryptoUtil.verifySignature(expectedData, payload.signature, payload.signerId);

            if (!isValid) {
                tm.rollback();
                throw new SecurityException("Signature verification failed for key: " + key);
            }

            tm.commit();
            return payload.jsonValue;

        } catch (Exception e) {
            if (tm.getStatus() == jakarta.transaction.Status.STATUS_ACTIVE) {
                tm.rollback();
            }
            throw e;
        }
    }

    @Override
    public void close() {
        if (cacheManager != null && cacheManager.getStatus().allowInvocations()) {
            cacheManager.stop();
            System.out.println("Node fully disconnected.");
        }
    }
}
