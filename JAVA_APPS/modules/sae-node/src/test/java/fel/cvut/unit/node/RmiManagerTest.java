package fel.cvut.unit.node;

import fel.cvut.node.Address;
import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.interNodeCommunication.SaeNodes;
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

    private static final String PIN_1 = "a".repeat(96);
    private static final String PIN_2 = "b".repeat(96);

    private static SaeNodes labNodes() {
        return SaeNodes.of(List.of(
                new SaeNodes.Entry("sae-1", "Alice", "Prague", new Address("127.0.0.1", 2010), PIN_1),
                new SaeNodes.Entry("sae-2", "Bob", "Berlin", new Address("127.0.0.1", 2020), PIN_2)));
    }

    @Test
    void knownNodesComeFromTheSaeDirectory() {
        RmiManager manager = new RmiManager(new Address("127.0.0.1", 2010), null, "sae-1", labNodes());
        List<String> ids = manager.getKnownSaeIds();
        assertEquals(List.of("sae-1", "sae-2"), ids);
        List<RmiManager.SaeNode> nodes = manager.getKnownSaeNodes();
        assertEquals(List.of(new RmiManager.SaeNode("sae-1", "Prague"), new RmiManager.SaeNode("sae-2", "Berlin")), nodes);
        assertThrows(UnsupportedOperationException.class, () -> nodes.add(new RmiManager.SaeNode("x", "y")));
        assertThrows(UnsupportedOperationException.class, () -> ids.add("x"));
        assertEquals(List.of(), new RmiManager(new Address("127.0.0.1", 2999)).getKnownSaeNodes());
    }



    @Test
    void connectBySaeIdValidatesSaeIdBeforeNetwork() {
        RmiManager manager = new RmiManager(new Address("127.0.0.1", 2999), null, "sae-1", labNodes());
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
        assertEquals("127.0.0.1", new RmiManager(new Address("127.0.0.1", 2999), " ", null, null).bindHost());
        assertEquals("10.0.0.5", new RmiManager(new Address("node.example", 2999), "10.0.0.5", null, null).bindHost());
    }

    @Test
    void startWithoutSaeDirectoryFailsClosed() throws Exception {
        RmiManager manager = new RmiManager(new Address("127.0.0.1", 2999));
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, null, null);
        fel.cvut.node.NodeCommands receiver = org.mockito.Mockito.mock(fel.cvut.node.NodeCommands.class);
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> manager.start(receiver, ctx));
        assertEquals("Failed to start RMI manager.", ex.getMessage());
        assertTrue(ex.getCause().getMessage().contains(SaeNodes.ENV_FILE), ex.getCause().getMessage());
        assertFalse(manager.isRunning());
    }

    @Test
    void forSelfTakesAdvertisedAddressFromOwnEntry() {
        RmiManager manager = RmiManager.forSelf(labNodes(), "sae-2", null);
        assertEquals(new Address("127.0.0.1", 2020), manager.address());
        assertEquals("Bob", manager.selfEntry().name());
        assertEquals("127.0.0.1", manager.bindHost(), "bind defaults to the own entry's hostname");
        assertEquals("10.0.0.5", RmiManager.forSelf(labNodes(), "sae-2", "10.0.0.5").bindHost());
        IllegalStateException unknown = assertThrows(IllegalStateException.class,
                () -> RmiManager.forSelf(labNodes(), "sae-9", null));
        assertTrue(unknown.getMessage().contains("sae-9"), unknown.getMessage());
    }
}
