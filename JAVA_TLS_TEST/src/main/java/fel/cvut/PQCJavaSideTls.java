package fel.cvut;

import fel.cvut.TLS.WolfSslDualSign;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.SecureRandom;

public class PQCJavaSideTls {

    // Point this to the newly created PKCS12 file
    private static final String P12_FILE = "../tls_usb_test/certs/server.p12";
    private static final String ALT_PRIVATE_KEY_FILE = "../tls_usb_test/certs/dilithium-server.priv";
    private static final char[] P12_PASS = "password".toCharArray();

    public static void main(String[] args) throws Exception {
        // 1. Load the Primary Keys using STANDARD Java PKCS12 KeyStore
        File p12File = new File(P12_FILE);
        System.out.println("Loading KeyStore from: " + p12File.getAbsolutePath());

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(p12File)) {
            ks.load(fis, P12_PASS);
        }

        // 2. Initialize the Standard Java KeyManager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, P12_PASS);

        // 3. Register Provider (loads wolfssljni from java.library.path)
        Security.insertProviderAt(new WolfSSLProvider(), 1);
        com.wolfssl.WolfSSL.debuggingON();
        com.wolfssl.WolfSSL.setLoggingCb((level, message) -> System.err.println("NATIVE: " + message));
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "wolfJSSE");

        // 4. Initialize Context WITH the KeyManager!
        // This is what passes the ECC key down to the native wolfSSL engine.
        sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

        // 5. Apply dual-sign settings (alt private key + sigspec) via low-level JNI API.
        WolfSslDualSign.configureServerDualSign(
                sslContext,
                new File(ALT_PRIVATE_KEY_FILE).getAbsolutePath()
        );

        // 6. Configure the Server Socket
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(11111);
        SSLParameters params = serverSocket.getSSLParameters();
        params.setProtocols(new String[]{"TLSv1.3"});
        serverSocket.setSSLParameters(params);

        System.out.println("Standard ECC Server started at port 11111.");

        while (true) {
            try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                WolfSslDualSign.startServerHandshake(socket);
                System.out.println("Handshake Success! Cipher: " + socket.getSession().getCipherSuite());
                WolfSslDualSign.requireHybridNegotiatedOnConnection(socket);
                System.out.println("Dual signature (CKS BOTH) confirmed.");
            } catch (Exception e) {
                System.err.println("Handshake failed: " + e.getMessage());
            }
        }
    }
}