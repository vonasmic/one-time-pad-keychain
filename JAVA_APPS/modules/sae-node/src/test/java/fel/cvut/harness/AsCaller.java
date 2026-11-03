package fel.cvut.harness;

import fel.cvut.node.NodeCommands;
import fel.cvut.node.interNodeCommunication.RmiCallerContext;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.concurrent.Callable;

/**
 * Test stand-in for the pinned-TLS caller binding: runs {@link NodeCommands} calls with a fixed
 * authenticated SAE ID in {@link RmiCallerContext}. Export the returned proxy with
 * {@link InProcessRmi#export} so the binding happens on the RMI server thread.
 */
public final class AsCaller {

    private AsCaller() {
    }

    public static NodeCommands bind(String callerSaeId, NodeCommands target) {
        return (NodeCommands) Proxy.newProxyInstance(
                NodeCommands.class.getClassLoader(),
                new Class<?>[]{NodeCommands.class},
                (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return switch (method.getName()) {
                            case "equals" -> proxy == args[0];
                            case "hashCode" -> System.identityHashCode(proxy);
                            default -> "AsCaller[" + callerSaeId + " -> " + target + "]";
                        };
                    }
                    return call(callerSaeId, () -> {
                        try {
                            return method.invoke(target, args);
                        } catch (InvocationTargetException ex) {
                            Throwable cause = ex.getCause();
                            if (cause instanceof Exception e) {
                                throw e;
                            }
                            throw (Error) cause;
                        }
                    });
                });
    }

    public static <T> T call(String callerSaeId, Callable<T> action) throws Exception {
        return RmiCallerContext.callAs(callerSaeId, action);
    }

    /** Void variant for statements. */
    public static void run(String callerSaeId, ThrowingRunnable action) throws Exception {
        RmiCallerContext.callAs(callerSaeId, () -> {
            action.run();
            return null;
        });
    }

    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Exception;
    }
}
