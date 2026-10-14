package fel.cvut.integration.rmi;

import fel.cvut.harness.JceAesGcm;
import fel.cvut.harness.MockKme;
import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.SaeSqliteExtension;
import fel.cvut.node.Address;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.NodeRef;
import fel.cvut.node.PeerRecordSync;
import fel.cvut.node.ProvisionSession;
import fel.cvut.node.interNodeCommunication.KnownPeers;
import fel.cvut.node.interNodeCommunication.NodeCommandsService;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.SharedKeyMaterialStore;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.tls.SoftwareTls;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static fel.cvut.harness.SaeFixtures.PEER_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;

/**
 * Real Java RMI over pure-PQC mutual TLS between two in-process SAE nodes, each backed by its own
 * SQLite database. {@link RmiManager} binds the registry on {@code address.port} and exports the
 * remote object on {@code 40000 + address.port}, so both ports are picked free at runtime.
 * {@link RmiManager#connectBySaeId} resolves addresses from the bundled {@code sae-nodes.json}
 * (fixed ports 2010/2020/2030), so the origin uses a spy that redirects to {@link RmiManager#connect}.
 */
@Tag("integration")
@Timeout(180)
class RmiTlsTwoNodeTest {

    @RegisterExtension
    static final SaeSqliteExtension SQLITE = new SaeSqliteExtension();

    private static SSLContext tls;

    private RmiManager peerRmi;

    @BeforeAll
    static void pki(@TempDir Path dir) throws Exception {
        SoftwareTls.installSoftware();
        KeyPair rootKeys = mlDsa();
        X500Name rootName = new X500Name("CN=rmi-it-root");
        JcaX509v3CertificateBuilder rb = new JcaX509v3CertificateBuilder(rootName, BigInteger.ONE, new Date(),
                new Date(System.currentTimeMillis() + 86_400_000L), rootName, rootKeys.getPublic());
        rb.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509Certificate root = sign(rb, rootKeys.getPrivate());
        KeyPair nodeKeys = mlDsa();
        X509Certificate leaf = sign(new JcaX509v3CertificateBuilder(root, BigInteger.TWO, new Date(),
                new Date(System.currentTimeMillis() + 86_400_000L), new X500Name("CN=sae-node"),
                nodeKeys.getPublic()), rootKeys.getPrivate());
        Path rootPem = dir.resolve("root-ca.pem");
        Path leafPem = dir.resolve("node.pem");
        Path keyPem = dir.resolve("node-key.pem");
        write(rootPem, root);
        write(leafPem, leaf);
        write(keyPem, nodeKeys.getPrivate());
        // RmiManager keeps one JVM-wide TLS context, so both in-process nodes share one identity.
        tls = SoftwareTls.createContextFromPem(leafPem, keyPem, rootPem);
        // F-01/F-02: that shared leaf is "self" to the pinning layer; name it as the origin SAE so
        // calls made with it are authorised as the origin.
    }

    @AfterEach
    void stop() {
        if (peerRmi != null) {
            peerRmi.stop();
        }
    }

    @Test
    void pingAndRecordQueriesTravelOverRmiTls() throws Exception {
        Address peerAddress = freeAddress();
        NodeCommandsService peerService = peerService(peerAddress);
        peerRmi = pinned(peerAddress);
        peerRmi.start(peerService, tls);
        assertTrue(peerRmi.isRunning());

        NodeCommands remote = new RmiManager(new Address("127.0.0.1", 1)).connect(peerAddress);
        assertTrue(remote.ping(null).startsWith("pong"));
        assertEquals(null, remote.getRecordMetadata(HASH_2, HASH_1));
        assertEquals(AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                remote.synchronize(SaeFixtures.header(HASH_2, HASH_1, ORIGIN_SAE), ORIGIN_SAE));
        AtomicRecordStateMap.RecordMetadata meta = remote.getRecordMetadata(HASH_2, HASH_1);
        assertEquals(AtomicRecordStateMap.RecordAvailability.RECORD_SYNCHRONIZATION, meta.recordAvailability());
        assertTrue(remote.lockFetch(HASH_2, HASH_1, ORIGIN_SAE));
        assertEquals(ORIGIN_SAE, remote.removeRecord(HASH_2, HASH_1).saeId());
        assertEquals(0, SaeFixtures.countRecords(SQLITE.peer()));
    }

    @Test
    void fullExchangeOverRealRmiFinalizesBothDatabases() throws Exception {
        try (MockKme kme = new MockKme()) {
            SSLContext plain = SSLContext.getInstance("TLS");
            plain.init(null, null, null);
            Address peerAddress = freeAddress();
            SharedKeyMaterialStore peerStore = SaeFixtures.keyStore(SQLITE.peer(), JceAesGcm.mockHsm());
            AtomicRecordStateMap peerMap = SaeFixtures.stateMap(PEER_SAE, SQLITE.peer());
            peerRmi = pinned(peerAddress);
            peerRmi.start(new NodeCommandsService(new NodeRef(peerAddress, PEER_SAE), peerMap,
                    new Qkd014Client(kme.baseUrl(), plain, SoftwareTls.TlsProfile.CLASSICAL),
                    peerStore, new RmiManager(peerAddress)), tls);

            RmiManager originRmi = spy(new RmiManager(new Address("127.0.0.1", 1)));
            doAnswer(inv -> originRmi.connect(peerAddress)).when(originRmi).connectBySaeId(PEER_SAE);
            AtomicRecordStateMap originMap = SaeFixtures.stateMap(ORIGIN_SAE, SQLITE.origin());
            assertEquals(AtomicRecordStateMap.SynchronizeOutcome.INSERTED,
                    originMap.synchronize(SaeFixtures.header(HASH_1, HASH_2, PEER_SAE), ORIGIN_SAE));
            PeerRecordSync sync = new PeerRecordSync(SaeFixtures.originRef(), originMap, originRmi,
                    new Qkd014Client(kme.baseUrl(), plain, SoftwareTls.TlsProfile.CLASSICAL));

            ProvisionSession.Exchange.Result result = sync.completeNewExchange(
                    SaeFixtures.record(HASH_1, HASH_2, PEER_SAE, List.of()), SaeFixtures.uplink());

            List<String> material = assertInstanceOf(
                    ProvisionSession.Exchange.Result.Generated.class, result).keyMaterial();
            assertEquals(material, peerStore.readPayload(HASH_2, HASH_1).orElseThrow());
            assertEquals(AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    originMap.get(HASH_1, HASH_2).orElseThrow().recordAvailability());
            assertEquals(AtomicRecordStateMap.RecordAvailability.RECORD_SHARED,
                    peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability());
            // finalisation over RMI as the origin does it
            assertTrue(originRmi.connect(peerAddress).markOriginProvisioned(HASH_2, HASH_1));
            assertEquals(AtomicRecordStateMap.RecordAvailability.ORIGIN_PROVISIONED,
                    peerMap.get(HASH_2, HASH_1).orElseThrow().recordAvailability());
        }
    }

    @Test
    void peerRefusalPropagatesAsRemoteExceptionOverTheWire() throws Exception {
        Address peerAddress = freeAddress();
        peerRmi = pinned(peerAddress);
        peerRmi.start(peerService(peerAddress), tls);
        NodeCommands remote = peerRmi.connect(peerAddress);

        RemoteException ex = assertThrows(RemoteException.class, () -> remote.insert(
                SaeFixtures.record(HASH_2, HASH_1, ORIGIN_SAE, List.of("key-1")), ORIGIN_SAE));
        assertEquals(0, SaeFixtures.countRecords(SQLITE.peer()));
    }

    @Test
    void stopUnexportsAndSameAddressCanBeRestarted() throws Exception {
        Address peerAddress = freeAddress();
        peerRmi = pinned(peerAddress);
        peerRmi.start(peerService(peerAddress), tls);
        peerRmi.start(peerService(peerAddress), tls); // idempotent while running
        NodeCommands stale = peerRmi.connect(peerAddress);
        assertTrue(stale.ping(null).startsWith("pong"));

        peerRmi.stop();
        assertFalse(peerRmi.isRunning());
        assertThrows(RemoteException.class, () -> stale.ping(null),
                "stub of an unexported object must fail");

        peerRmi = pinned(peerAddress);
        peerRmi.start(peerService(peerAddress), tls);
        assertTrue(peerRmi.connect(peerAddress).ping(null).startsWith("pong"));
    }

    // ---------------------------------------------------------------- helpers

    private static NodeCommandsService peerService(Address address) {
        NodeRef ref = new NodeRef(address, PEER_SAE);
        return new NodeCommandsService(ref,
                SaeFixtures.stateMap(PEER_SAE, SQLITE.peer()),
                SaeFixtures.mockQkd(),
                SaeFixtures.keyStore(SQLITE.peer(), JceAesGcm.mockHsm()),
                new RmiManager(address));
    }

    /** Server-side manager whose (shared) TLS identity resolves to the origin SAE. */
    private static RmiManager pinned(Address address) {
        return new RmiManager(address, null, KnownPeers.of(ORIGIN_SAE, Map.of()));
    }

    /** Registry port p and export port 40000+p must both be free. */
    private static Address freeAddress() throws IOException {
        for (int attempt = 0; attempt < 200; attempt++) {
            int p = ThreadLocalRandom.current().nextInt(20_000, 25_000);
            if (free(p) && free(40_000 + p)) {
                return new Address("127.0.0.1", p);
            }
        }
        throw new IOException("no free RMI port pair");
    }

    private static boolean free(int port) {
        try (ServerSocket s = new ServerSocket(port, 1, InetAddress.getLoopbackAddress())) {
            s.setReuseAddress(true);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static KeyPair mlDsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44);
        return kpg.generateKeyPair();
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder b, PrivateKey key) throws Exception {
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                b.build(new JcaContentSignerBuilder(key.getAlgorithm())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(key)));
    }

    private static void write(Path path, Object o) throws IOException {
        try (JcaPEMWriter w = new JcaPEMWriter(Files.newBufferedWriter(path))) {
            w.writeObject(o);
        }
    }
}