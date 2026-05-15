package fel.cvut.bouncyCastle;

import org.jgroups.util.DefaultSocketFactory;
import org.jgroups.util.SocketFactory;
import org.jgroups.util.TLS;
import org.jgroups.util.TLSClientAuth;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.FileInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyStore;

/**
 * Builds {@link TLS} for JGroups {@code TCP.tls(...)} — not for global {@code setSocketFactory}.
 */
public final class PqcSocketFactory {

    private PqcSocketFactory() {
    }

    public static TLS createJGroupsTls(String nodeId) throws Exception {
        SSLContext sslContext = loadContextForNode(nodeId);
        return new TLS() {
            @Override
            public SocketFactory createSocketFactory(SSLContext context) {
                DefaultSocketFactory factory = new DefaultSocketFactory(context);
                factory.setSocketConfigurator(PqcSocketFactory::configureClientSocket);
                factory.setServerSocketConfigurator(PqcSocketFactory::configureServerSocket);
                return factory;
            }
        }.enabled(true)
                .setSSLContext(sslContext)
                .setProtocols(new String[]{"TLSv1.3"})
                .setClientAuth(TLSClientAuth.NEED);
    }

    public static SSLContext loadContextForNode(String nodeId) throws Exception {
        BouncyCastleTLS.ensureProvidersRegistered();
        Path certsDir = Path.of(System.getProperty("pqc.certs.dir", "certs"));
        String pass = System.getProperty("pqc.keystore.password", "password");
        String certName = certNameFor(nodeId);

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        try (FileInputStream fis = new FileInputStream(certsDir.resolve(certName + ".p12").toFile())) {
            ks.load(fis, pass.toCharArray());
        }

        KeyStore ts = KeyStore.getInstance("PKCS12", "BC");
        try (FileInputStream fis = new FileInputStream(certsDir.resolve("root-ca.p12").toFile())) {
            ts.load(fis, pass.toCharArray());
        }

        return BouncyCastleTLS.createBouncyCastleContext(ks, pass.toCharArray(), ts);
    }

    public static String certNameFor(String nodeId) {
        return switch (nodeId.toUpperCase()) {
            case "ALICE" -> "Alice";
            case "BOB" -> "Bob";
            case "CAROL" -> "Carol";
            default -> nodeId;
        };
    }

    private static void configureClientSocket(Socket socket) {
        if (socket instanceof SSLSocket sslSocket) {
            SSLParameters params = sslSocket.getSSLParameters();
            BouncyCastleTLS.applyPqcTlsParameters(params);
            sslSocket.setSSLParameters(params);
        }
    }

    private static void configureServerSocket(ServerSocket socket) {
        if (socket instanceof SSLServerSocket sslServerSocket) {
            sslServerSocket.setNeedClientAuth(true);
            SSLParameters params = sslServerSocket.getSSLParameters();
            BouncyCastleTLS.applyPqcTlsParameters(params);
            sslServerSocket.setSSLParameters(params);
        }
    }
}
