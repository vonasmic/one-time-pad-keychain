package fel.cvut.terminal;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Newline-delimited JSON wire protocol between a node's terminal gateway and the standalone
 * terminal app: one {@link Request} per line, one matching {@link Response} per line. Kept
 * intentionally tiny (no RMI, no node-internal types) so the terminal app only needs {@code
 * fel.cvut.terminal} + {@code fel.cvut.tls} to run.
 */
public final class TerminalWireProtocol {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TerminalWireProtocol() {
    }

    public record Option(String id, String label) {
    }

    /** {@code type} is {@code "SELECT"}, {@code "CONFIRM"}, or {@code "NOTIFY"}; only the matching fields are set. */
    public record Request(String type, List<Option> clients, List<Option> saes, String message) {
        public static Request select(List<Option> clients, List<Option> saes) {
            return new Request("SELECT", clients, saes, null);
        }

        public static Request confirm(String message) {
            return new Request("CONFIRM", null, null, message);
        }

        public static Request notify(String message) {
            return new Request("NOTIFY", null, null, message);
        }
    }

    /** {@code type} mirrors the request it answers; only the matching fields are set. */
    public record Response(String type, String clientId, String saeId, boolean confirmed) {
        public static Response select(String clientId, String saeId) {
            return new Response("SELECT", clientId, saeId, false);
        }

        public static Response confirm(boolean confirmed) {
            return new Response("CONFIRM", null, null, confirmed);
        }

        public static Response notifyAck() {
            return new Response("NOTIFY", null, null, false);
        }
    }

    public static void writeRequest(OutputStream out, Request request) throws IOException {
        writeLine(out, request);
    }

    public static Request readRequest(BufferedReader in) throws IOException {
        return MAPPER.readValue(requireLine(in, "terminal request"), Request.class);
    }

    public static void writeResponse(OutputStream out, Response response) throws IOException {
        writeLine(out, response);
    }

    public static Response readResponse(BufferedReader in) throws IOException {
        return MAPPER.readValue(requireLine(in, "terminal response"), Response.class);
    }

    public static BufferedReader reader(InputStream in) {
        return new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
    }

    private static void writeLine(OutputStream out, Object value) throws IOException {
        String json = MAPPER.writeValueAsString(value);
        out.write((json + "\n").getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private static String requireLine(BufferedReader in, String what) throws IOException {
        String line = in.readLine();
        if (line == null) {
            throw new IOException("Connection closed while waiting for " + what);
        }
        return line;
    }
}
