package fel.cvut.node.interNodeCommunication;

import fel.cvut.harness.SaeFixtures;
import fel.cvut.harness.TestPki;
import fel.cvut.node.Address;
import fel.cvut.node.NodeCommands;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.tls.SoftwareTls;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F-01/F-02/F-06 over real PURE_PQC TLS: peer pinning, caller binding on the RMI read thread,
 * bind address, and the argument filter on a real exported object.
 */
@Tag("integration")
@Timeout(120)
class RmiPeerPinningTest {

    private static final SoftwareTls.TlsProfile PQC = SoftwareTls.TlsProfile.PURE_PQC;
    private static TestPki.Leaf saeA;
    private static TestPki.Leaf saeB;
    private static TestPki.Leaf rogue;

    @BeforeAll
    static void pki(@TempDir Path dir) throws Exception {
        SoftwareTls.installSoftware();
        TestPki pki = new TestPki(dir, "CN=rmi-pinning-test-ca");
        saeA = pki.leaf("sae-1");
        saeB = pki.leaf("sae-2");
        rogue = pki.leaf("rogue");
    }

    private static KnownPeers serverPins() {
        return KnownPeers.of("sae-1", Map.of("sae-2", KnownPeers.spkiSha256(saeB.cert())));
    }

    @Test
    void pinnedPeerIsBoundAsCallerOnTheReadingThread() throws Exception {
        assertEquals(Optional.of("sae-2"), callerSeenByServer(saeB));
    }

    @Test
    void ownLeafIsBoundAsSelf() throws Exception {
        assertEquals(Optional.of("sae-1"), callerSeenByServer(saeA));
    }

    @Test
    void caSignedButUnpinnedPeerIsDisconnectedBeforeAnyRead() throws Exception {
        ExecutionException ex = assertThrows(ExecutionException.class, () -> callerSeenByServer(rogue));
        assertInstanceOf(SSLPeerUnverifiedException.class, ex.getCause());
        assertTrue(ex.getCause().getMessage().contains("not pinned"), ex.getCause().getMessage());
    }

    @Test
    void clientRejectsServerThatIsNotTheExpectedPinnedSae() throws Exception {
        try (SSLServerSocket tls = SoftwareTls.createServerSocket(
                0, saeA.context(), PQC, true, InetAddress.getLoopbackAddress());
             ServerSocket server = RmiPeerPinning.pinningServerSocket(tls, serverPins())) {
            CompletableFuture<Optional<String>> ignored = acceptAndRead(server);
            KnownPeers clientPins = KnownPeers.of("sae-2", Map.of("sae-1", KnownPeers.spkiSha256(saeA.cert())));
            try (SSLSocket ok = SoftwareTls.createClientSocket("127.0.0.1", tls.getLocalPort(), saeB.context(), PQC)) {
                RmiPeerPinning.verifyServer(ok, clientPins, "sae-1");
            }
            acceptAndRead(server);
            SSLSocket wrongSae = SoftwareTls.createClientSocket("127.0.0.1", tls.getLocalPort(), saeB.context(), PQC);
            assertThrows(SSLPeerUnverifiedException.class,
                    () -> RmiPeerPinning.verifyServer(wrongSae, clientPins, "sae-3"));
            assertTrue(wrongSae.isClosed());
            acceptAndRead(server);
            SSLSocket unpinned = SoftwareTls.createClientSocket("127.0.0.1", tls.getLocalPort(), saeB.context(), PQC);
            assertThrows(SSLPeerUnverifiedException.class,
                    () -> RmiPeerPinning.verifyServer(unpinned, KnownPeers.of("sae-2", Map.of()), null));
            ignored.cancel(true);
        }
    }

    @Test
    void endpointsMapToConfiguredSaeIds() {
        assertEquals("sae-1", RmiManager.expectedSaeIdFor("127.0.0.1", 2010));
        assertEquals("sae-2", RmiManager.expectedSaeIdFor("127.0.0.1", 42020));
        assertNull(RmiManager.expectedSaeIdFor("127.0.0.1", 9));
        assertNull(RmiManager.expectedSaeIdFor("192.0.2.1", 2010));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void realRmiBindsCallerFiltersArgumentsAndListensOnlyOnBindAddress() throws Exception {
        int port = freeRmiPort();
        RecordingCommands receiver = new RecordingCommands();
        RmiManager manager = new RmiManager(new Address("127.0.0.1", port), "127.0.0.1", serverPins());
        manager.start(receiver, saeA.context());
        try {
            NodeCommands stub = manager.connect(new Address("127.0.0.1", port));
            assertNull(stub.removeRecord(HASH_1, HASH_2));
            assertEquals(List.of("removeRecord:sae-1"), receiver.calls, "dispatch thread sees the pinned caller");

            List raw = new ArrayList();
            raw.add(new HashMap<String, String>());
            ClientRecord smuggled = SaeFixtures.record(HASH_1, HASH_2, "sae-1", raw);
            assertThrows(RemoteException.class, () -> stub.insert(smuggled, "sae-1"));
            assertEquals(1, receiver.calls.size(), "filtered call must not reach the service");

            assertTrue(stub.insert(SaeFixtures.record(HASH_1, HASH_2, "sae-1", List.of("key-1")), "sae-1"));
            assertEquals("insert:sae-1", receiver.calls.get(1));

            for (InetAddress other : nonLoopbackIpv4()) {
                assertThrows(IOException.class, () -> {
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(other, port), 2000);
                    }
                }, "registry must not listen on " + other);
                assertThrows(IOException.class, () -> {
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(other, 40000 + port), 2000);
                    }
                }, "object port must not listen on " + other);
            }
        } finally {
            manager.stop();
        }
    }

    /** Server with pins {sae-2}; one client connects with {@code client}, writes a byte; returns the bound caller. */
    private static Optional<String> callerSeenByServer(TestPki.Leaf client) throws Exception {
        try (SSLServerSocket tls = SoftwareTls.createServerSocket(
                0, saeA.context(), PQC, true, InetAddress.getLoopbackAddress());
             ServerSocket server = RmiPeerPinning.pinningServerSocket(tls, serverPins())) {
            CompletableFuture<Optional<String>> seen = acceptAndRead(server);
            try (SSLSocket socket = SoftwareTls.createClientSocket(
                    "127.0.0.1", tls.getLocalPort(), client.context(), PQC)) {
                try {
                    socket.getOutputStream().write(42);
                    socket.getOutputStream().flush();
                } catch (IOException closedByServer) {
                    // An unpinned client may already be disconnected; the server-side result decides.
                }
                return seen.get(30, TimeUnit.SECONDS);
            }
        }
    }

    private static CompletableFuture<Optional<String>> acceptAndRead(ServerSocket server) {
        CompletableFuture<Optional<String>> result = new CompletableFuture<>();
        Thread.ofPlatform().daemon().start(() -> {
            try {
                Socket accepted = server.accept();
                try {
                    RmiCallerContext.clear();
                    int b = accepted.getInputStream().read();
                    result.complete(b == 42 ? RmiCallerContext.currentSaeId() : Optional.empty());
                } finally {
                    RmiCallerContext.clear();
                    accepted.close();
                }
            } catch (Throwable t) {
                result.completeExceptionally(t);
            }
        });
        return result;
    }

    private static int freeRmiPort() throws IOException {
        for (int attempt = 0; attempt < 200; attempt++) {
            int port = ThreadLocalRandom.current().nextInt(21000, 25000);
            try (ServerSocket a = new ServerSocket(port); ServerSocket b = new ServerSocket(40000 + port)) {
                return port;
            } catch (IOException busy) {
                // try another
            }
        }
        throw new IOException("no free RMI port pair");
    }

    private static List<InetAddress> nonLoopbackIpv4() throws IOException {
        List<InetAddress> out = new ArrayList<>();
        for (NetworkInterface nif : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!nif.isUp() || nif.isLoopback()) {
                continue;
            }
            for (InetAddress a : Collections.list(nif.getInetAddresses())) {
                if (a instanceof Inet4Address && !a.isLoopbackAddress()) {
                    out.add(a);
                }
            }
        }
        return out;
    }

    /** Records "method:caller" for each dispatched call. */
    private static final class RecordingCommands implements NodeCommands {
        final List<String> calls = Collections.synchronizedList(new ArrayList<>());

        private void record(String method) {
            calls.add(method + ":" + RmiCallerContext.currentSaeId().orElse("<none>"));
        }

        @Override
        public String ping(Address from) {
            record("ping");
            return "pong";
        }

        @Override
        public AtomicRecordStateMap.RecordMetadata getRecordMetadata(String h1, String h2) {
            record("getRecordMetadata");
            return null;
        }

        @Override
        public AtomicRecordStateMap.SynchronizeOutcome synchronize(ClientRecord.ClientHeader header, String issuing) {
            record("synchronize");
            return AtomicRecordStateMap.SynchronizeOutcome.NOT_INSERTED;
        }

        @Override
        public boolean lockFetch(String h1, String h2, String issuing) {
            record("lockFetch");
            return false;
        }

        @Override
        public boolean insert(ClientRecord clientRecord, String issuing) {
            record("insert");
            return true;
        }

        @Override
        public AtomicRecordStateMap.RecordMetadata removeRecord(String h1, String h2) {
            record("removeRecord");
            return null;
        }

        @Override
        public void deleteShare(String h1, String h2) {
            record("deleteShare");
        }

        @Override
        public boolean markOriginProvisioned(String h1, String h2) {
            record("markOriginProvisioned");
            return false;
        }
    }
}
