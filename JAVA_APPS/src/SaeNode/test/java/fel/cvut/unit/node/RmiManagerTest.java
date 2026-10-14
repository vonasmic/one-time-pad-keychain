package fel.cvut.unit.node;

import fel.cvut.node.Address;
import fel.cvut.node.interNodeCommunication.RmiManager;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** RmiManager paths that need no live RMI registry or PQC TLS handshake. */
@Tag("unit")
class RmiManagerTest {

    @Test
    void knownNodesComeFromBundledConfiguration() {
        List<String> ids = RmiManager.getKnownSaeIds();
        assertTrue(ids.containsAll(List.of("sae-1", "sae-2", "sae-3")), ids.toString());
        List<RmiManager.SaeNode> nodes = RmiManager.getKnownSaeNodes();
        assertEquals(ids.size(), nodes.size());
        assertTrue(nodes.contains(new RmiManager.SaeNode("sae-1", "Prague")), nodes.toString());
        assertThrows(UnsupportedOperationException.class, () -> nodes.add(new RmiManager.SaeNode("x", "y")));
        assertThrows(UnsupportedOperationException.class, () -> ids.add("x"));
    }



    @Test
    void connectBySaeIdValidatesSaeIdBeforeNetwork() {
        RmiManager manager = new RmiManager(new Address("127.0.0.1", 2999));
        assertThrows(IllegalArgumentException.class, () -> manager.connectBySaeId(null));
        assertThrows(IllegalArgumentException.class, () -> manager.connectBySaeId("  "));
        IllegalArgumentException unknown = assertThrows(IllegalArgumentException.class,
                () -> manager.connectBySaeId("sae-404"));
        assertTrue(unknown.getMessage().contains("sae-404"));
    }


    @Test
    void startFailureLeavesManagerStoppedAndTlsUninstalled() throws Exception {
        RmiManager manager = new RmiManager(new Address("127.0.0.1", 2999));
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, null, null);
        assertThrows(NullPointerException.class, () -> manager.start(null, null));

        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> manager.start(null, ctx));
        assertEquals("Failed to start RMI manager.", ex.getMessage());
        assertFalse(manager.isRunning());

        IllegalStateException noTls = assertThrows(IllegalStateException.class,
                () -> manager.connect(new Address("127.0.0.1", 2010)));
        assertTrue(noTls.getMessage().contains("TLS context not installed"));
    }

    @Test
    void bindAddressDefaultsToAdvertisedHostAndCanBeOverridden() {
        assertEquals("127.0.0.1", new RmiManager(new Address("127.0.0.1", 2999)).bindHost());
        assertEquals("127.0.0.1", new RmiManager(new Address("127.0.0.1", 2999), " ", null).bindHost());
        assertEquals("10.0.0.5", new RmiManager(new Address("node.example", 2999), "10.0.0.5", null).bindHost());
    }

    @Test
    void startWithoutPinnedPeersFailsClosed() throws Exception {
        RmiManager manager = new RmiManager(new Address("127.0.0.1", 2999));
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, null, null);
        fel.cvut.node.NodeCommands receiver = org.mockito.Mockito.mock(fel.cvut.node.NodeCommands.class);
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> manager.start(receiver, ctx));
        assertEquals("Failed to start RMI manager.", ex.getMessage());
        assertTrue(ex.getCause().getMessage().contains(RmiManager.ENV_KNOWN_PEERS), ex.getCause().getMessage());
        assertFalse(manager.isRunning());
    }

    @Test
    void fromEnvironmentRequiresKnownPeersFile() {
        org.junit.jupiter.api.Assumptions.assumeTrue(System.getenv(RmiManager.ENV_KNOWN_PEERS) == null);
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> RmiManager.fromEnvironment(new fel.cvut.node.NodeRef(new Address("127.0.0.1", 2999), "sae-1")));
        assertTrue(ex.getMessage().contains(RmiManager.ENV_KNOWN_PEERS));
    }
}
