package fel.cvut.harness;

import fel.cvut.node.NodeCommands;
import fel.cvut.node.interNodeCommunication.RmiManager;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * In-process SAE network for tests: every (caller, target) pair gets its own exported stub whose
 * server side runs with the caller's SAE ID bound, the way pinned TLS binds it in production.
 */
public final class TestRmiNetwork implements AutoCloseable {

    private final Map<String, NodeCommands> services = new ConcurrentHashMap<>();
    private final Map<String, InProcessRmi> exports = new ConcurrentHashMap<>();
    private final Set<String> unreachable = ConcurrentHashMap.newKeySet();

    public TestRmiNetwork register(String saeId, NodeCommands service) {
        services.put(saeId, service);
        return this;
    }

    /** RMI stub for calls from {@code callerSaeId} to {@code targetSaeId}. */
    public NodeCommands stub(String callerSaeId, String targetSaeId) throws RemoteException, NotBoundException {
        if (unreachable.contains(targetSaeId)) {
            throw new RemoteException("SAE " + targetSaeId + " unreachable (test)");
        }
        NodeCommands service = services.get(targetSaeId);
        if (service == null) {
            throw new NotBoundException("unknown SAE " + targetSaeId);
        }
        try {
            return exports.computeIfAbsent(callerSaeId + "->" + targetSaeId, k -> {
                try {
                    return InProcessRmi.export(AsCaller.bind(callerSaeId, service));
                } catch (RemoteException e) {
                    throw new IllegalStateException(e);
                }
            }).stub();
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof RemoteException re) {
                throw re;
            }
            throw e;
        }
    }

    /** Mock {@link RmiManager} as seen by node {@code callerSaeId}. */
    public RmiManager rmiFor(String callerSaeId) throws RemoteException, NotBoundException {
        RmiManager rmi = mock(RmiManager.class);
        when(rmi.connectBySaeId(anyString()))
                .thenAnswer(invocation -> stub(callerSaeId, invocation.getArgument(0)));
        return rmi;
    }

    public void setUnreachable(String saeId, boolean down) {
        if (down) {
            unreachable.add(saeId);
        } else {
            unreachable.remove(saeId);
        }
    }

    @Override
    public void close() {
        exports.values().forEach(InProcessRmi::close);
        exports.clear();
    }
}
