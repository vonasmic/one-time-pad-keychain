package fel.cvut;

import fel.cvut.TLS.NativeTlsServer;
import fel.cvut.TLS.TLSSocket;

import java.nio.charset.StandardCharsets;

public class PQCJavaSideTls {

    private static final int DEFAULT_PORT = 11111;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;

        System.out.println("Starting native hybrid PQC TLS server on port " + port + ".");
        System.out.println("Run from JAVA_TLS_CLIENTPUBLICKEY; certs in certs/native/server/ (make certs-native in tls_native).");

        try (NativeTlsServer server = new NativeTlsServer(port)) {
            System.out.println("Server listening on port " + port + ".");

            while (true) {
                try (TLSSocket conn = server.accept()) {
                    System.out.println("TLS handshake complete (native wolfSSL).");

                    byte[] request = conn.read();
                    if (request != null && request.length > 0) {
                        System.out.println("Received: " + new String(request, StandardCharsets.UTF_8).trim());
                    }

                    String reply = "Hello from Hybrid Auth Server!\n";
                    conn.write(reply.getBytes(StandardCharsets.UTF_8));
                } catch (Exception e) {
                    System.err.println("Connection error: " + e.getMessage());
                }
            }
        }
    }
}
