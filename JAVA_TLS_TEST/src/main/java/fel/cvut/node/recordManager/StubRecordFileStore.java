package fel.cvut.node.recordManager;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Persists generated QKD key records into a local stub file (JSONL).
 */
public class StubRecordFileStore {

    private static final Path STUB_FILE_PATH = Path.of("stub-records.jsonl");
    private final ObjectMapper objectMapper;

    public StubRecordFileStore() {
        this.objectMapper = new ObjectMapper();
    }

    public synchronized void write(ClientRecord clientRecord) throws IOException {
        Objects.requireNonNull(clientRecord, "clientRecord must not be null");
        ClientRecord.ClientHeader header = clientRecord.getClientHeader();
        ClientRecord.ClientData data = clientRecord.getClientData();
        validateClientHash(header.clientHash1(), "clientHash1");
        validateClientHash(header.clientHash2(), "clientHash2");
        Objects.requireNonNull(header.saeId(), "secondSaeId must not be null");
        Objects.requireNonNull(data.payload(), "payload must not be null");

        StubRecordEntry entry = new StubRecordEntry(
                header.clientHash1(),
                header.clientHash2(),
                header.saeId(),
                data.payload(),
                System.currentTimeMillis()
        );
        String jsonLine = objectMapper.writeValueAsString(entry) + System.lineSeparator();

        Path parent = STUB_FILE_PATH.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(
                STUB_FILE_PATH,
                jsonLine,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.APPEND
        );
    }

    public synchronized List<StubRecordEntry> readAllRecords() throws IOException {
        if (!Files.exists(STUB_FILE_PATH)) {
            return List.of();
        }

        List<StubRecordEntry> records = new ArrayList<>();
        for (String line : Files.readAllLines(STUB_FILE_PATH)) {
            if (line == null || line.isBlank()) {
                continue;
            }
            records.add(objectMapper.readValue(line, StubRecordEntry.class));
        }
        return List.copyOf(records);
    }

    public synchronized Optional<List<String>> readPayload(String clientHash1, String clientHash2, String saeId)
            throws IOException {
        validateClientHash(clientHash1, "clientHash1");
        validateClientHash(clientHash2, "clientHash2");
        Objects.requireNonNull(saeId, "saeId must not be null");

        for (StubRecordEntry entry : readAllRecords()) {
            if (matches(entry, clientHash1, clientHash2, saeId)) {
                return Optional.of(entry.getPayload());
            }
        }
        return Optional.empty();
    }

    public synchronized boolean remove(String clientHash1, String clientHash2, String saeId) throws IOException {
        validateClientHash(clientHash1, "clientHash1");
        validateClientHash(clientHash2, "clientHash2");
        Objects.requireNonNull(saeId, "saeId must not be null");

        if (!Files.exists(STUB_FILE_PATH)) {
            return false;
        }

        List<String> lines = Files.readAllLines(STUB_FILE_PATH);
        List<String> remaining = new ArrayList<>();
        boolean removed = false;
        for (String line : lines) {
            if (line == null || line.isBlank()) {
                continue;
            }
            StubRecordEntry entry = objectMapper.readValue(line, StubRecordEntry.class);
            if (!removed && matches(entry, clientHash1, clientHash2, saeId)) {
                removed = true;
                continue;
            }
            remaining.add(line);
        }

        if (!removed) {
            return false;
        }

        if (remaining.isEmpty()) {
            Files.deleteIfExists(STUB_FILE_PATH);
        } else {
            Files.writeString(STUB_FILE_PATH, String.join(System.lineSeparator(), remaining) + System.lineSeparator());
        }
        return true;
    }

    private static boolean matches(StubRecordEntry entry, String clientHash1, String clientHash2, String saeId) {
        return Objects.equals(entry.getClientHash1(), clientHash1)
                && Objects.equals(entry.getClientHash2(), clientHash2)
                && Objects.equals(entry.getSecondSaeId(), saeId);
    }

    private static void validateClientHash(String hash, String fieldName) {
        if (hash == null || hash.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be null or blank");
        }
    }

    public static final class StubRecordEntry {
        private String clientHash1;
        private String clientHash2;
        private String secondSaeId;
        private List<String> payload;
        private long createdAt;

        public StubRecordEntry() {
            // required by Jackson
        }

        public StubRecordEntry(
                String clientHash1,
                String clientHash2,
                String secondSaeId,
                List<String> payload,
                long createdAt
        ) {
            this.clientHash1 = Objects.requireNonNull(clientHash1, "clientHash1 must not be null");
            this.clientHash2 = Objects.requireNonNull(clientHash2, "clientHash2 must not be null");
            this.secondSaeId = Objects.requireNonNull(secondSaeId, "secondSaeId must not be null");
            this.payload = Objects.requireNonNull(payload, "payload must not be null");
            this.createdAt = createdAt;
        }

        public String getClientHash1() {
            return clientHash1;
        }

        public String getClientHash2() {
            return clientHash2;
        }

        public String getSecondSaeId() {
            return secondSaeId;
        }

        public List<String> getPayload() {
            return payload;
        }

        public long getCreatedAt() {
            return createdAt;
        }
    }
}
