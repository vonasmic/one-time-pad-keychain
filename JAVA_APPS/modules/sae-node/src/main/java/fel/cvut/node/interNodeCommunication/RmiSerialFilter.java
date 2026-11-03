package fel.cvut.node.interNodeCommunication;

import fel.cvut.node.NodeCommands;

import java.io.ObjectInputFilter;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Allowlists for Java serialization on the inter-SAE RMI link.
 *
 * <p>{@link #CALLS} covers the arguments of {@link fel.cvut.node.NodeCommands} calls: {@code Address},
 * {@code ClientRecord} and its nested records, {@code String}/{@code Integer}, and the JDK list
 * implementations a {@code List<String>} payload can arrive as.
 *
 * <p>{@link #REPLIES} covers what a caller reads back: the return types of {@code NodeCommands},
 * the exceptions a call can end with, and the registry stub. It is installed process-wide
 * ({@link #installForReplies}), because RMI has no per-call hook on the client. Streams that set
 * their own filter (the exported object with {@link #CALLS}, the registry, DGC) keep theirs.
 *
 * <p>Everything else, and anything beyond the depth, reference, array, or byte limits, is rejected
 * before {@code readObject}.
 */
public final class RmiSerialFilter {

    private static final Logger LOG = Logger.getLogger(RmiSerialFilter.class.getName());

    private static final String LIMITS_PATTERN = String.join(";",
            "maxdepth=8",
            "maxrefs=20000",
            "maxarray=10000",
            "maxbytes=4194304");

    private static final String LISTS = String.join(";",
            "java.util.ArrayList",
            "java.util.Arrays$ArrayList",
            "java.util.CollSer",
            "java.util.ImmutableCollections$List12",
            "java.util.ImmutableCollections$ListN",
            "java.util.Collections$EmptyList",
            "java.util.Collections$SingletonList",
            "java.util.Collections$UnmodifiableCollection",
            "java.util.Collections$UnmodifiableList",
            "java.util.Collections$UnmodifiableRandomAccessList");

    /** JEP 290 pattern for call arguments; exposed for tests and for {@code -Djdk.serialFilter} reuse. */
    public static final String PATTERN = String.join(";",
            LIMITS_PATTERN,
            "fel.cvut.node.Address",
            "fel.cvut.node.recordManager.ClientRecord",
            "fel.cvut.node.recordManager.ClientRecord$ClientHeader",
            "fel.cvut.node.recordManager.ClientRecord$ClientData",
            "java.lang.String",
            "java.lang.Integer",
            "java.lang.Number",
            "java.lang.Object",
            LISTS,
            "!*");

    /** Reply limits: an exception with its cause chain nests deeper than call arguments. */
    private static final String REPLY_LIMITS_PATTERN = String.join(";",
            "maxdepth=16",
            "maxrefs=20000",
            "maxarray=10000",
            "maxbytes=4194304");

    /**
     * JEP 290 pattern for return values and the registry stub. Exceptions and the stub proxy
     * class are checked in code.
     */
    public static final String REPLY_PATTERN = String.join(";",
            REPLY_LIMITS_PATTERN,
            "fel.cvut.node.recordManager.AtomicRecordStateMap$RecordMetadata",
            "fel.cvut.node.recordManager.AtomicRecordStateMap$RecordAvailability",
            "fel.cvut.node.recordManager.AtomicRecordStateMap$DeleteOutcome",
            "java.lang.Enum",
            "java.time.Ser",
            "java.time.Instant",
            "java.lang.String",
            "java.lang.Integer",
            "java.lang.Number",
            "java.lang.Object",
            "java.lang.StackTraceElement",
            LISTS,
            "fel.cvut.node.NodeCommands",
            "java.rmi.Remote",
            "java.lang.reflect.Proxy",
            "java.rmi.server.RemoteObject",
            "java.rmi.server.RemoteObjectInvocationHandler",
            "java.rmi.server.RemoteStub",
            "javax.rmi.ssl.SslRMIClientSocketFactory",
            "fel.cvut.node.interNodeCommunication.RmiManager$PqcTlsRmiClientSocketFactory",
            "java.rmi.dgc.Lease",
            "java.rmi.dgc.VMID",
            "java.rmi.server.UID",
            "!*");

    /** Packages whose {@link Throwable} subclasses a reply may carry (call failures and their causes). */
    private static final Set<String> THROWABLE_PACKAGES = Set.of(
            "java.lang", "java.io", "java.rmi", "java.rmi.server", "java.sql");

    private static final ObjectInputFilter REPLY_LIMITS = ObjectInputFilter.Config.createFilter(REPLY_LIMITS_PATTERN);
    private static final ObjectInputFilter REPLY_CLASSES = ObjectInputFilter.Config.createFilter(REPLY_PATTERN);

    /** Filter installed on the exported {@code NodeCommands} object. */
    public static final ObjectInputFilter CALLS = ObjectInputFilter.Config.createFilter(PATTERN);

    /** Filter for everything a {@code NodeCommands} caller deserializes. */
    public static final ObjectInputFilter REPLIES = RmiSerialFilter::checkReply;

    private RmiSerialFilter() {
    }

    /**
     * Installs {@link #REPLIES} as the JVM-wide filter. A filter that is already set (for example
     * by {@code -Djdk.serialFilter}) is kept, because the JVM-wide filter can be set only once.
     */
    public static synchronized void installForReplies() {
        ObjectInputFilter current = ObjectInputFilter.Config.getSerialFilter();
        if (current == REPLIES) {
            return;
        }
        if (current != null) {
            LOG.warning("A JVM-wide serial filter is already set (jdk.serialFilter); RMI replies use it");
            return;
        }
        ObjectInputFilter.Config.setSerialFilter(REPLIES);
    }

    private static ObjectInputFilter.Status checkReply(ObjectInputFilter.FilterInfo info) {
        if (REPLY_LIMITS.checkInput(info) == ObjectInputFilter.Status.REJECTED) {
            return reject(info);
        }
        Class<?> type = info.serialClass();
        if (type == null) {
            return ObjectInputFilter.Status.UNDECIDED;
        }
        while (type.isArray()) {
            type = type.getComponentType();
        }
        if (type.isPrimitive()) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        if (Throwable.class.isAssignableFrom(type) && trustedThrowable(type)) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        if (Proxy.isProxyClass(type)) {
            return stubProxy(type) ? ObjectInputFilter.Status.ALLOWED : reject(info);
        }
        ObjectInputFilter.Status status = REPLY_CLASSES.checkInput(info);
        return status == ObjectInputFilter.Status.ALLOWED ? status : reject(info);
    }

    /** The registry returns the {@code NodeCommands} stub as a dynamic proxy. */
    private static boolean stubProxy(Class<?> type) {
        for (Class<?> iface : type.getInterfaces()) {
            if (iface != NodeCommands.class && iface != Remote.class) {
                return false;
            }
        }
        return type.getInterfaces().length > 0;
    }

    private static boolean trustedThrowable(Class<?> type) {
        String pkg = type.getPackageName();
        return THROWABLE_PACKAGES.contains(pkg) || pkg.equals("fel.cvut") || pkg.startsWith("fel.cvut.");
    }

    private static ObjectInputFilter.Status reject(ObjectInputFilter.FilterInfo info) {
        LOG.warning("RMI reply rejected by the serial filter: class=" + info.serialClass()
                + " depth=" + info.depth() + " refs=" + info.references()
                + " array=" + info.arrayLength() + " bytes=" + info.streamBytes());
        return ObjectInputFilter.Status.REJECTED;
    }
}
