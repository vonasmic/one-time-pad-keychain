package fel.cvut.qkd;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import fel.cvut.tls.NodeTls;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Qkd014ClientTest {

    private HttpServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void getKeyWithKeyIdsBatchesUsingStatusLimit() throws Exception {
        int maxPerRequest = 3;
        AtomicInteger oversizePosts = new AtomicInteger();
        AtomicInteger posts = new AtomicInteger();
        AtomicInteger gets = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serveStatus("sae-1", maxPerRequest);
        server.createContext("/api/v1/keys/sae-1/dec_keys", exchange -> {
            try {
                String method = exchange.getRequestMethod();
                List<String> ids;
                if ("GET".equals(method)) {
                    gets.incrementAndGet();
                    URI uri = exchange.getRequestURI();
                    String query = uri.getQuery() == null ? "" : uri.getQuery();
                    ids = new ArrayList<>();
                    for (String part : query.split("&")) {
                        if (part.startsWith("key_ID=")) {
                            ids.add(part.substring("key_ID=".length()));
                        }
                    }
                } else {
                    posts.incrementAndGet();
                    InputStream body = exchange.getRequestBody();
                    KeyIdsRequest request = new ObjectMapper().readValue(body, KeyIdsRequest.class);
                    ids = new ArrayList<>();
                    if (request.key_IDs != null) {
                        for (KeyIdEntry entry : request.key_IDs) {
                            ids.add(entry.key_ID);
                        }
                    }
                    if (ids.size() > maxPerRequest) {
                        oversizePosts.incrementAndGet();
                    }
                }
                KeyContainer container = new KeyContainer();
                container.keys = new ArrayList<>(ids.size());
                for (String id : ids) {
                    KeyItem item = new KeyItem();
                    item.key_ID = id;
                    item.key = "Zg==";
                    container.keys.add(item);
                }
                byte[] json = new ObjectMapper().writeValueAsBytes(container);
                exchange.sendResponseHeaders(200, json.length);
                exchange.getResponseBody().write(json);
            } finally {
                exchange.close();
            }
        });
        server.start();

        int total = maxPerRequest + 1;
        List<String> keyIds = new ArrayList<>(total);
        for (int i = 0; i < total; i++) {
            keyIds.add("key-" + i);
        }

        KeyContainer result = client().getKeyWithKeyIds("sae-1", keyIds);

        assertEquals(0, oversizePosts.get());
        assertEquals(1, posts.get());
        assertEquals(1, gets.get());
        assertEquals(total, result.keys.size());
        assertEquals("key-0", result.keys.get(0).key_ID);
        assertEquals("key-" + (total - 1), result.keys.get(total - 1).key_ID);
    }

    @Test
    void qkdErrorOnDecKeysIsSerializableThroughRemoteException() throws Exception {
        ErrorResponse error = new ErrorResponse();
        error.message = "number of requested keys exceeds max_key_per_request";
        Qkd014ClientException qkdEx = new Qkd014ClientException(error.message, 400, error);
        RemoteException remote = new RemoteException("Target record insert failed while resolving key IDs.", qkdEx);

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(remote);
        }
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            RemoteException copy = assertInstanceOf(RemoteException.class, in.readObject());
            assertTrue(copy.getCause() instanceof Qkd014ClientException);
            assertEquals(error.message, copy.getCause().getMessage());
        }
    }

    @Test
    void oversizeUnbatchedRequestSurfacesKmeError() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serveStatus("sae-1", 8);
        server.createContext("/api/v1/keys/sae-1/dec_keys", exchange -> {
            ErrorResponse error = new ErrorResponse();
            error.message = "too many keys";
            byte[] json = new ObjectMapper().writeValueAsBytes(error);
            try {
                exchange.sendResponseHeaders(400, json.length);
                exchange.getResponseBody().write(json);
            } finally {
                exchange.close();
            }
        });
        server.start();

        Qkd014ClientException ex = assertThrows(Qkd014ClientException.class, () ->
                client().getKeyWithKeyIds("sae-1", List.of("only-one")));
        assertEquals(400, ex.getHttpStatusCode());
        assertEquals("too many keys", ex.getMessage());
    }

    @Test
    void getStatusParsesKmeLimits() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serveStatus("sae-2", 7, 80_000);
        server.start();

        KmeStatus status = client().getStatus("sae-2");
        assertEquals(80_000, status.max_key_size);
        assertEquals(7, status.max_key_per_request);
        assertEquals(80_000, status.maxKeySizeBits());
        assertEquals(7, status.maxKeysPerRequest());
    }

    @Test
    void getStatusParsesStatusExtension() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/keys/sae-2/status", exchange -> {
            String json = """
                    {
                      "source_KME_ID": "kme-1",
                      "target_KME_ID": "kme-2",
                      "master_SAE_ID": "sae-1",
                      "slave_SAE_ID": "sae-2",
                      "key_size": 256,
                      "stored_key_count": 1000,
                      "max_key_count": 10000,
                      "max_key_per_request": 8,
                      "max_key_size": 4096,
                      "min_key_size": 64,
                      "max_SAE_ID_count": 0,
                      "status_extension": {"vendor_health": "GREEN"}
                    }
                    """;
            byte[] body = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try {
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            } finally {
                exchange.close();
            }
        });
        server.start();

        KmeStatus status = client().getStatus("sae-2");
        assertEquals("GREEN", status.status_extension.get("vendor_health"));
        assertEquals(8, status.maxKeysPerRequest());
    }

    private void serveStatus(String saeId, int maxPerRequest) {
        serveStatus(saeId, maxPerRequest, 512);
    }

    private void serveStatus(String saeId, int maxPerRequest, int maxKeySizeBits) {
        server.createContext("/api/v1/keys/" + saeId + "/status", exchange -> {
            KmeStatus status = new KmeStatus();
            status.max_key_size = maxKeySizeBits;
            status.max_key_per_request = maxPerRequest;
            byte[] json = new ObjectMapper().writeValueAsBytes(status);
            try {
                exchange.sendResponseHeaders(200, json.length);
                exchange.getResponseBody().write(json);
            } finally {
                exchange.close();
            }
        });
    }

    private Qkd014Client client() throws Exception {
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, null, null);
        return new Qkd014Client(
                "http://127.0.0.1:" + server.getAddress().getPort(),
                ssl,
                NodeTls.TlsProfile.CLASSICAL
        );
    }
}
