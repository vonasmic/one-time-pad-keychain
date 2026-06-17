package fel.cvut.node;

import java.io.Serializable;
import java.util.Objects;

/**
 * Immutable reference to a node, containing address information.
 */
public class NodeRef implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private final Address address;
    private final String nodeId;
    
    public NodeRef(Address address, String nodeId) {
        this.address = Objects.requireNonNull(address, "address must not be null");
        String normalizedNodeId = Objects.requireNonNull(nodeId, "nodeId must not be null").trim();
        if (normalizedNodeId.isEmpty()) {
            throw new IllegalArgumentException("nodeId must not be blank");
        }
        this.nodeId = normalizedNodeId;
    }
    
    public Address getAddress() {
        return address;
    }
    
    public String getNodeId() {
        return nodeId;
    }
    
    @Override
    public String toString() {
        return "NodeRef[addr=" + address + ", id=" + nodeId + "]";
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        NodeRef other = (NodeRef) obj;
        if (address == null && other.address == null) return true;
        if (address == null || other.address == null) return false;
        return address.compareTo(other.address) == 0;
    }
    
    @Override
    public int hashCode() {
        if (address == null) return 0;
        return address.hostname.hashCode() * 31 + address.port;
    }
}

