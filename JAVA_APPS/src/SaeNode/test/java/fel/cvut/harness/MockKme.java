package fel.cvut.harness;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.KeyItem;
import fel.cvut.qkd.KmeStatus;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Minimal ETSI GS QKD 014 KME on loopback HTTP: {@code status}, {@code enc_keys} (master)
 * and {@code dec_keys} GET/POST (slave). Keys handed out by enc_keys are remembered by ID
 * and each can be fetched once by dec_keys, like a real KME pair.
 */
public final class MockKme implements AutoCloseable {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpServer server;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, String> issued = new ConcurrentHashMap<>();
    public final AtomicInteger encCalls = new AtomicInteger();
    public final AtomicInteger decCalls = new AtomicInteger();
    public volatile int keySizeBits = 256;
    public volatile int storedKeys = 1000;
    public volatile int maxPerRequest = 4;
    public volatile int maxKeySizeBits = 1024;
    /** When set, dec_keys answers with this HTTP status and an ETSI error body. */
    public volatile int failDecKeysWith = 0;

    public MockKme() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/keys/", this::handle);
        server.start();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public int issuedCount() {
        return issued.size();
    }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            String[] parts = exchange.getRequestURI().getPath().split("/");
            // /api/v1/keys/{sae}/{op}
            String op = parts[parts.length - 1];
            switch (op) {
                case "status" -> respond(exchange, 200, status());
                case "enc_keys" -> respond(exchange, 200, encKeys(query(exchange)));
                case "dec_keys" -> decKeys(exchange);
                default -> respond(exchange, 404, Map.of("message", "unknown op " + op));
            }
        } catch (RuntimeException ex) {
            respond(exchange, 500, Map.of("message", String.valueOf(ex.getMessage())));
        }
    }

    private KmeStatus status() {
        KmeStatus s = new KmeStatus();
        s.key_size = keySizeBits;
        s.stored_key_count = storedKeys;
        s.max_key_count = 100_000;
        s.max_key_per_request = maxPerRequest;
        s.max_key_size = maxKeySizeBits;
        s.min_key_size = 64;
        return s;
    }

    private KeyContainer encKeys(Map<String, String> query) {
        encCalls.incrementAndGet();
        int number = Integer.parseInt(query.getOrDefault("number", "1"));
        int size = Integer.parseInt(query.getOrDefault("size", String.valueOf(keySizeBits)));
        if (size > maxKeySizeBits) {
            throw new IllegalArgumentException("size too large");
        }
        KeyContainer c = new KeyContainer();
        c.keys = new ArrayList<>();
        for (int i = 0; i < number; i++) {
            byte[] material = new byte[size / 8];
            random.nextBytes(material);
            KeyItem item = new KeyItem();
            item.key_ID = UUID.randomUUID().toString();
            item.key = Base64.getEncoder().encodeToString(material);
            issued.put(item.key_ID, item.key);
            c.keys.add(item);
        }
        storedKeys = Math.max(0, storedKeys - number * Math.max(1, size / keySizeBits));
        return c;
    }

    private void decKeys(HttpExchange exchange) throws IOException {
        decCalls.incrementAndGet();
        if (failDecKeysWith != 0) {
            respond(exchange, failDecKeysWith, Map.of("message", "dec_keys refused by test KME"));
            return;
        }
        List<String> ids = new ArrayList<>();
        if ("GET".equals(exchange.getRequestMethod())) {
            String id = query(exchange).get("key_ID");
            if (id != null) {
                ids.add(id);
            }
        } else {
            JsonNode body = JSON.readTree(exchange.getRequestBody());
            for (JsonNode entry : body.path("key_IDs")) {
                ids.add(entry.path("key_ID").asText());
            }
        }
        KeyContainer c = new KeyContainer();
        c.keys = new ArrayList<>();
        for (String id : ids) {
            String key = issued.remove(id);
            if (key == null) {
                respond(exchange, 400, Map.of("message", "key_ID not found: " + id));
                return;
            }
            KeyItem item = new KeyItem();
            item.key_ID = id;
            item.key = key;
            c.keys.add(item);
        }
        respond(exchange, 200, c);
    }

    private static Map<String, String> query(HttpExchange exchange) {
        Map<String, String> out = new ConcurrentHashMap<>();
        String raw = exchange.getRequestURI().getRawQuery();
        if (raw == null) {
            return out;
        }
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                out.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return out;
    }

    private static void respond(HttpExchange exchange, int status, Object body) throws IOException {
        byte[] bytes = JSON.writeValueAsBytes(body);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}