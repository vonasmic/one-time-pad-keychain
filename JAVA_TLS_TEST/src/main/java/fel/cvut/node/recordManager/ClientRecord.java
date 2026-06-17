package fel.cvut.node.recordManager;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

public class ClientRecord implements Serializable {

    private static final long serialVersionUID = 1L;

    private final ClientHeader clientHeader;
    private final ClientData clientData;

    public ClientRecord(String clientHash1, String clientHash2, List<String> payload, String secondSaeId) {
        this(new ClientHeader(clientHash1, clientHash2, secondSaeId), new ClientData(payload));
    }

    public ClientRecord(ClientHeader clientHeader, ClientData clientData) {
        this.clientHeader = Objects.requireNonNull(clientHeader, "clientHeader must not be null");
        this.clientData = Objects.requireNonNull(clientData, "clientData must not be null");
    }

    public ClientHeader getClientHeader() {
        return clientHeader;
    }

    public ClientData getClientData() {
        return clientData;
    }

    public String getClientHash1() {
        return clientHeader.clientHash1();
    }

    public String getClientHash2() {
        return clientHeader.clientHash2();
    }

    public String getSecondSaeId() {
        return clientHeader.saeId();
    }

    public List<String> getPayload() {
        return clientData.payload();
    }

    public ClientRecord withPayload(List<String> updatedPayload) {
        return new ClientRecord(clientHeader, new ClientData(updatedPayload));
    }

    public ClientRecord withSecondSaeId(String secondSaeId) {
        return new ClientRecord(
                new ClientHeader(clientHeader.clientHash1(), clientHeader.clientHash2(), secondSaeId),
                clientData
        );
    }

    @Override
    public String toString() {
        return "ClientRecord{"
                + "clientHash1='" + clientHeader.clientHash1() + '\''
                + ", clientHash2='" + clientHeader.clientHash2() + '\''
                + ", secondSaeId='" + clientHeader.saeId() + '\''
                + ", payloadSize=" + clientData.payload().size()
                + '}';
    }

    public record ClientHeader(String clientHash1, String clientHash2, String saeId) implements Serializable {
        private static final long serialVersionUID = 1L;

        public ClientHeader {
            validateNonBlank(clientHash1, "clientHash1");
            validateNonBlank(clientHash2, "clientHash2");
            validateNonBlank(saeId, "saeId");
        }
    }

    public record ClientData(List<String> payload) implements Serializable {
        private static final long serialVersionUID = 1L;

        public ClientData {
            Objects.requireNonNull(payload, "payload must not be null");
        }
    }

    private static void validateNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be null or blank");
        }
    }
}
