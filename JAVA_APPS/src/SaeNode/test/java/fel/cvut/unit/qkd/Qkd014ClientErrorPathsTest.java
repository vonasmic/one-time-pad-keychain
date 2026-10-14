package fel.cvut.unit.qkd;

import com.sun.net.httpserver.HttpServer;
import fel.cvut.qkd.KeyContainer;
import fel.cvut.qkd.KmeStatus;
import fel.cvut.qkd.Qkd014Client;
import fel.cvut.qkd.Qkd014ClientException;
import fel.cvut.tls.SoftwareTls;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class Qkd014ClientErrorPathsTest {

    private HttpServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void constructorValidatesBaseUrl() throws Exception {
        SSLContext ssl = ssl();
        assertThrows(NullPointerException.class, () -> new Qkd014Client(null, ssl, null));
        assertThrows(IllegalArgumentException.class, () -> new Qkd014Client("   ", ssl, null));
        assertThrows(IllegalArgumentException.class, () -> new Qkd014Client("127.0.0.1:443", ssl, null));
        IllegalArgumentException scheme = assertThrows(IllegalArgumentException.class,
                () -> new Qkd014Client("ftp://kme.example", ssl, null));
        assertTrue(scheme.getMessage().contains("http or https"));
        assertThrows(IllegalArgumentException.class, () -> new Qkd014Client("http:///nohost", ssl, null));
        assertThrows(NullPointerException.class, () -> new Qkd014Client("https://kme.example", null, null));
    }


    @Test
    void getKeyEncodesPathAndQueryAndStripsTrailingSlash() throws Exception {
        AtomicReference<String> rawPath = new AtomicReference<>();
        AtomicReference<String> rawQuery = new AtomicReference<>();
        start();
        server.createContext("/api/v1/keys/", exchange -> {
            rawPath.set(exchange.getRequestURI().getRawPath());
            rawQuery.set(exchange.getRequestURI().getRawQuery());
            respond(exchange, 200, "{\"keys\":[]}");
        });
        Qkd014Client client = new Qkd014Client(baseUrl() + "/", ssl(), null);

        KeyContainer keys = client.getKey("sae 2", 3, 32);

        assertNotNull(keys);
        assertEquals("/api/v1/keys/sae%202/enc_keys", rawPath.get());
        assertEquals("number=3&size=32", rawQuery.get());

        client.getKey("sae-2", null, null);
        assertNull(rawQuery.get());
    }

    @Test
    void errorJsonMessageAndStatusAreSurfaced() throws Exception {
        start();
        server.createContext("/api/v1/keys/sae-1/status", exchange ->
                respond(exchange, 400, "{\"message\":\"slave SAE unknown\"}"));
        Qkd014ClientException ex = assertThrows(Qkd014ClientException.class, () -> client().getStatus("sae-1"));
        assertEquals("slave SAE unknown", ex.getMessage());
        assertEquals(400, ex.getHttpStatusCode());
        assertNotNull(ex.getErrorResponse());
        assertEquals("slave SAE unknown", ex.getErrorResponse().message);
    }

    @Test
    void htmlErrorPageIsSummarizedNotDumped() throws Exception {
        start();
        String html = "<!DOCTYPE html><html><body>Bad gateway</body></html>";
        server.createContext("/api/v1/keys/sae-1/status", exchange -> respond(exchange, 502, html));
        Qkd014ClientException ex = assertThrows(Qkd014ClientException.class, () -> client().getStatus("sae-1"));
        assertEquals("QKD API call failed with HTTP 502: HTML error page (" + html.length() + " bytes)",
                ex.getMessage());
        assertEquals(502, ex.getHttpStatusCode());
        assertNull(ex.getErrorResponse());
    }

    @Test
    void valueTooLongLineIsExtracted() throws Exception {
        start();
        String body = "Traceback\nERROR: value too long for type character varying(64)\nmore";
        server.createContext("/api/v1/keys/sae-1/status", exchange -> respond(exchange, 500, body));
        Qkd014ClientException ex = assertThrows(Qkd014ClientException.class, () -> client().getStatus("sae-1"));
        assertEquals("QKD API call failed with HTTP 500: value too long for type character varying(64)",
                ex.getMessage());
    }

    @Test
    void longPlainBodyIsTruncatedAndEmptyBodyOmitted() throws Exception {
        start();
        String longBody = "x".repeat(400);
        server.createContext("/api/v1/keys/long/status", exchange -> respond(exchange, 500, longBody));
        server.createContext("/api/v1/keys/empty/status", exchange -> respond(exchange, 503, ""));
        Qkd014ClientException longEx = assertThrows(Qkd014ClientException.class, () -> client().getStatus("long"));
        assertEquals("QKD API call failed with HTTP 500: " + "x".repeat(300) + "…", longEx.getMessage());
        Qkd014ClientException emptyEx = assertThrows(Qkd014ClientException.class, () -> client().getStatus("empty"));
        assertEquals("QKD API call failed with HTTP 503", emptyEx.getMessage());
    }

    @Test
    void blankJsonMessageFallsBackToStatusText() throws Exception {
        start();
        server.createContext("/api/v1/keys/sae-1/status", exchange ->
                respond(exchange, 401, "{\"message\":\"  \"}"));
        Qkd014ClientException ex = assertThrows(Qkd014ClientException.class, () -> client().getStatus("sae-1"));
        assertTrue(ex.getMessage().startsWith("QKD API call failed with HTTP 401"), ex.getMessage());
        assertNotNull(ex.getErrorResponse());
    }

    @Test
    void unparsableSuccessBodyIsReported() throws Exception {
        start();
        server.createContext("/api/v1/keys/sae-1/status", exchange -> respond(exchange, 200, "not json"));
        Qkd014ClientException ex = assertThrows(Qkd014ClientException.class, () -> client().getStatus("sae-1"));
        assertTrue(ex.getMessage().startsWith("Failed to parse successful QKD response"), ex.getMessage());
        assertEquals(-1, ex.getHttpStatusCode());
        assertNotNull(ex.getCause());
    }

    @Test
    void decKeysErrorPropagatesAfterStatus() throws Exception {
        start();
        server.createContext("/api/v1/keys/sae-1/status", exchange -> {
            KmeStatus status = new KmeStatus();
            status.max_key_size = 512;
            status.max_key_per_request = 4;
            respond(exchange, 200, new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(status));
        });
        server.createContext("/api/v1/keys/sae-1/dec_keys", exchange ->
                respond(exchange, 400, "{\"message\":\"key ID not found\"}"));
        Qkd014ClientException ex = assertThrows(Qkd014ClientException.class,
                () -> client().getKeyWithKeyIds("sae-1", List.of("k-1")));
        assertEquals("key ID not found", ex.getMessage());
        assertEquals(400, ex.getHttpStatusCode());
    }

    @Test
    void unreachableServerIsDescribedAsConnectivityProblem() throws Exception {
        int port;
        try (ServerSocket probe = new ServerSocket(0)) {
            port = probe.getLocalPort();
        }
        Qkd014Client client = new Qkd014Client("http://127.0.0.1:" + port, ssl(), null);
        Qkd014ClientException ex = assertThrows(Qkd014ClientException.class, () -> client.getStatus("sae-1"));
        assertTrue(ex.getMessage().startsWith("QKD server unreachable at http://127.0.0.1:" + port),
                ex.getMessage());
        assertEquals(-1, ex.getHttpStatusCode());
        assertNull(ex.getErrorResponse());
    }

    private void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private Qkd014Client client() throws Exception {
        return new Qkd014Client(baseUrl(), ssl(), SoftwareTls.TlsProfile.CLASSICAL);
    }

    private static SSLContext ssl() throws Exception {
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, null, null);
        return ssl;
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        try {
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) {
                exchange.getResponseBody().write(bytes);
            }
        } finally {
            exchange.close();
        }
    }
}