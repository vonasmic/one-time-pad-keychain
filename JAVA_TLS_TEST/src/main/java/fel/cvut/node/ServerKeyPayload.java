package fel.cvut.node;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
     * Reads from the stream until the accumulated bytes form a complete JSON payload.
     * Needed because TLS may deliver the payload across multiple read calls.
     */
    public static ServerKeyPayload readFrom(InputStream in) throws IOException {
        Objects.requireNonNull(in, "in must not be null");

        ByteArrayOutputStream buffer = new ByteArrayOutputStream(4096);
        IOException lastIncomplete = null;
        byte[] chunk = new byte[4096];

        while (buffer.size() < MAX_PAYLOAD_BYTES) {
            int n = in.read(chunk);
            if (n < 0) {
                break;
            }
            if (n == 0) {
                continue;
            }
            buffer.write(chunk, 0, n);
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
