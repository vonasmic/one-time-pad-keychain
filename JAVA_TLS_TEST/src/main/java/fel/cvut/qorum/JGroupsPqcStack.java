package fel.cvut.qorum;

import fel.cvut.bouncyCastle.PqcSocketFactory;
import org.infinispan.remoting.transport.jgroups.EmbeddedJGroupsChannelConfigurator;
import org.jgroups.conf.ProtocolConfiguration;
import org.jgroups.protocols.TCP;
import org.jgroups.stack.Protocol;

import java.util.List;
import java.util.Map;

public final class JGroupsPqcStack {

    private JGroupsPqcStack() {
    }

    public static List<ProtocolConfiguration> protocolConfigurations(int bindPort) {
        try {
            return List.of(
                    new ProtocolConfiguration("TCP", Map.of("bind_port", String.valueOf(bindPort))),
                    new ProtocolConfiguration("TCPPING", Map.of(
                            "initial_hosts", "127.0.0.1[11111],127.0.0.1[11112]",
                            "port_range", "2")),
                    new ProtocolConfiguration("MERGE3"),
                    new ProtocolConfiguration("FD_SOCK"),
                    new ProtocolConfiguration("FD_ALL3"),
                    new ProtocolConfiguration("VERIFY_SUSPECT"),
                    new ProtocolConfiguration("pbcast.NAKACK2"),
                    new ProtocolConfiguration("UNICAST3"),
                    new ProtocolConfiguration("pbcast.STABLE"),
                    new ProtocolConfiguration("pbcast.GMS"),
                    new ProtocolConfiguration("UFC"),
                    new ProtocolConfiguration("MFC"),
                    new ProtocolConfiguration("FRAG2")
            );
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build JGroups protocol stack", e);
        }
    }

    public static EmbeddedJGroupsChannelConfigurator createConfigurator(String stackName, int bindPort, String nodeId) {
        return new EmbeddedJGroupsChannelConfigurator(stackName, protocolConfigurations(bindPort), null) {
            @Override
            public void afterCreation(Protocol protocol) {
                super.afterCreation(protocol);
                if (protocol instanceof TCP tcp) {
                    try {
                        tcp.tls(PqcSocketFactory.createJGroupsTls(nodeId));
                    } catch (Exception e) {
                        throw new IllegalStateException("Failed to configure PQC TLS on TCP", e);
                    }
                }
            }
        };
    }

    public static int defaultPortFor(String nodeId) {
        return switch (nodeId) {
            case "Alice" -> 11111;
            case "Bob" -> 11112;
            default -> 11111;
        };
    }
}
