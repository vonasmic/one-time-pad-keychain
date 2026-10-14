package fel.cvut.node.interNodeCommunication;

import java.io.ObjectInputFilter;

/**
 * Allowlist for arguments of {@link fel.cvut.node.NodeCommands} calls (F-06).
 *
 * <p>Only the types the interface actually takes are accepted: {@code Address},
 * {@code ClientRecord} and its nested records, {@code String}/{@code Integer}, and the JDK list
 * implementations a {@code List<String>} payload can arrive as. Everything else, and anything
 * beyond the depth, reference, array, or byte limits, is rejected before {@code readObject}.
 */
public final class RmiSerialFilter {

    /** JEP 290 pattern; exposed for tests and for {@code -Djdk.serialFilter} reuse. */
    public static final String PATTERN = String.join(";",
            "maxdepth=8",
            "maxrefs=20000",
            "maxarray=10000",
            "maxbytes=4194304",
            "fel.cvut.node.Address",
            "fel.cvut.node.recordManager.ClientRecord",
            "fel.cvut.node.recordManager.ClientRecord$ClientHeader",
            "fel.cvut.node.recordManager.ClientRecord$ClientData",
            "java.lang.String",
            "java.lang.Integer",
            "java.lang.Number",
            "java.lang.Object",
            "java.util.ArrayList",
            "java.util.Arrays$ArrayList",
            "java.util.CollSer",
            "java.util.ImmutableCollections$List12",
            "java.util.ImmutableCollections$ListN",
            "java.util.Collections$EmptyList",
            "java.util.Collections$SingletonList",
            "java.util.Collections$UnmodifiableCollection",
            "java.util.Collections$UnmodifiableList",
            "java.util.Collections$UnmodifiableRandomAccessList",
            "!*");

    /** Filter installed on the exported {@code NodeCommands} object. */
    public static final ObjectInputFilter CALLS = ObjectInputFilter.Config.createFilter(PATTERN);

    private RmiSerialFilter() {
    }
}
