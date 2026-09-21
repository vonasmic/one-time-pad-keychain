package fel.cvut.utimaco;

import fel.cvut.tls.HsmNodeTls;
import fel.cvut.tls.SoftwareTls;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Loopback PQC TLS handshake probe: JCE installed, PQMI sign on ephemeral CXI per call.
 */
public final class HsmTlsProbe {

    private HsmTlsProbe() {
    }

    public static void main(String[] args) throws Exception {
        String nodeId = env("TLS_NODE_ID", "Alice");
        boolean jce = !hasArg(args, "--no-jce");

        System.out.println("[probe] ephemeral CXI per PQMI op, JCE install=" + jce);

        try (Pqmi pqmi = Pqmi.fromEnvironment()) {
            if (jce) {
                HsmNodeTls.createContextForNode(pqmi, nodeId);
            } else {
                pqmi.loadIdentityKey(pqmi.keyRefForNode(nodeId));
            }

            SSLContext ctx = HsmNodeTls.createContextForNode(pqmi, nodeId);
            int port = 0;
            SSLServerSocket server = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0);
            port = server.getLocalPort();
            server.setNeedClientAuth(false);
            server.setSSLParameters(SoftwareTls.parameters(SoftwareTls.TlsProfile.PURE_PQC));

            CompletableFuture<String> serverDone = CompletableFuture.supplyAsync(() -> {
                try (SSLServerSocket ss = server; SSLSocket peer = (SSLSocket) ss.accept()) {
                    peer.setSSLParameters(SoftwareTls.parameters(SoftwareTls.TlsProfile.PURE_PQC));
                    peer.startHandshake();
                    return peer.getSession().getCipherSuite();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            try (SSLSocket client = (SSLSocket) ctx.getSocketFactory().createSocket("127.0.0.1", port)) {
                client.setSSLParameters(SoftwareTls.parameters(SoftwareTls.TlsProfile.PURE_PQC));
                client.startHandshake();
                System.out.println("[probe] client handshake OK: " + client.getSession().getCipherSuite());
            }

            System.out.println("[probe] server handshake OK: " + serverDone.get(60, TimeUnit.SECONDS));
            System.out.println("[probe] PASS");
        }
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v.trim();
    }

    private static boolean hasArg(String[] args, String flag) {
        for (String arg : args) {
            if (flag.equals(arg)) {
                return true;
            }
        }
        return false;
    }
}
