package fel.cvut.node;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.TLS.TLSSocket;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

/**
 * Incoming server payload with local private key and candidate peer keys.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ServerKeyPayload {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final int MAX_PAYLOAD_BYTES = 64 * 1024;

    @JsonProperty("clientpublickey")
    private byte[] clientPublicKey;

    @JsonProperty("array")
    private List<SecondPartyKeyEntry> array;

    public ServerKeyPayload() {
        // required by Jackson
    }

    public byte[] getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(byte[] clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public List<SecondPartyKeyEntry> getArray() {
        return array;
    }

    public void setArray(List<SecondPartyKeyEntry> array) {
        this.array = array;
    }

    public static ServerKeyPayload fromBytes(byte[] rawJson) {
        Objects.requireNonNull(rawJson, "rawJson must not be null");
        try {
            return OBJECT_MAPPER.readValue(rawJson, ServerKeyPayload.class);
        } catch (IOException ex) {
            throw new IllegalArgumentException("Failed to parse server payload JSON.", ex);
        }
    }

    /**
     * Reads TLS records until the accumulated bytes form a complete payload.
     * Needed because each {@code wolfSSL_write} may arrive as a separate record.
     */
    public static ServerKeyPayload readFrom(TLSSocket socket) {
        Objects.requireNonNull(socket, "socket must not be null");

        ByteArrayOutputStream buffer = new ByteArrayOutputStream(4096);
        IOException lastIncomplete = null;

        while (buffer.size() < MAX_PAYLOAD_BYTES) {
            byte[] chunk = socket.read();
            if (chunk == null || chunk.length == 0) {
                break;
            }
            buffer.write(chunk, 0, chunk.length);
            try {
                return OBJECT_MAPPER.readValue(buffer.toByteArray(), ServerKeyPayload.class);
            } catch (IOException ex) {
                if (isIncompleteJson(ex)) {
                    lastIncomplete = ex;
                    continue;
                }
                throw new IllegalArgumentException("Failed to parse server payload JSON.", ex);
            }
        }

        if (lastIncomplete != null) {
            throw new IllegalArgumentException(
                    "Failed to parse server payload JSON after " + buffer.size() + " bytes.", lastIncomplete);
        }
        throw new IllegalArgumentException("Connection closed before a complete server payload was received.");
    }

    private static boolean isIncompleteJson(IOException ex) {
        for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
            String message = cause.getMessage();
            if (message != null && message.contains("Unexpected end-of-input")) {
                return true;
            }
        }
        return false;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class SecondPartyKeyEntry {
        @JsonProperty("secondPartyKey")
        private byte[] secondPartyKey;

        @JsonProperty("nickname")
        private String nickname;

        public SecondPartyKeyEntry() {
            // required by Jackson
        }

        public byte[] getSecondPartyKey() {
            return secondPartyKey;
        }

        public void setSecondPartyKey(byte[] secondPartyKey) {
            this.secondPartyKey = secondPartyKey;
        }

        public String getNickname() {
            return nickname;
        }

        public void setNickname(String nickname) {
            this.nickname = nickname;
        }
    }
}
