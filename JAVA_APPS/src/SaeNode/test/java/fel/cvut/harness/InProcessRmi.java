package fel.cvut.harness;

import fel.cvut.node.NodeCommands;

import java.rmi.NoSuchObjectException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

/**
 * Exports a {@link NodeCommands} implementation over plain JDK RMI (no TLS / HSM).
 */
public final class InProcessRmi implements AutoCloseable {

    private final NodeCommands implementation;
    private final NodeCommands stub;
    private volatile boolean exported = true;

    private InProcessRmi(NodeCommands implementation, NodeCommands stub) {
        this.implementation = implementation;
        this.stub = stub;
    }

    public static InProcessRmi export(NodeCommands implementation) throws RemoteException {
        NodeCommands stub = (NodeCommands) UnicastRemoteObject.exportObject(implementation, 0);
        return new InProcessRmi(implementation, stub);
    }

    public NodeCommands stub() {
        return stub;
    }

    public void unexport() {
        if (!exported) {
            return;
        }
        try {
            UnicastRemoteObject.unexportObject(implementation, true);
        } catch (NoSuchObjectException ignored) {
            // Already unexported.
        }
        exported = false;
    }

    @Override
    public void close() {
        unexport();
    }
}
