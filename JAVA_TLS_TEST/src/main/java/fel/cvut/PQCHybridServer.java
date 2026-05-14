package fel.cvut;

import fel.cvut.TLS.NativeTlsServer;
import fel.cvut.TLS.NativeTlsSocket;

import java.nio.charset.StandardCharsets;

public class PQCHybridServer {

    public static void main(String[] args) {

        NativeTlsServer server = new NativeTlsServer(11111);

        System.out.println("TLS Server started on port 11111");

        while (true) {

            NativeTlsSocket client = server.accept();

            System.out.println("Client connected (TLS established)");

            byte[] msg = client.read();

            if (msg != null) {
                String text = new String(msg, StandardCharsets.UTF_8);
                System.out.println("Client says: " + text);
            }

            String reply = "Hello from Hybrid Auth Server!\n";
            client.write(reply.getBytes(StandardCharsets.UTF_8));

            client.close();
        }
    }
}