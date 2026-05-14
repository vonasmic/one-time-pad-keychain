package fel.cvut.raft;

import org.jgroups.JChannel;
import org.jgroups.protocols.*;
import org.jgroups.protocols.pbcast.GMS;
import org.jgroups.protocols.pbcast.NAKACK2;
import org.jgroups.protocols.pbcast.STABLE;
import org.jgroups.protocols.raft.ELECTION;
import org.jgroups.protocols.raft.RAFT;
import org.jgroups.raft.blocks.ReplicatedStateMachine;
import org.jgroups.util.TLS;
import org.jgroups.util.Util;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class PqcRaftMap {

    private static final String P12_FILE = "../tls_usb_test/certs/server.p12";
    private static final char[] P12_PASS = "password".toCharArray();

    private final JChannel channel;
    private final ReplicatedStateMachine<String, String> rsm;

    public PqcRaftMap(String nodeId, int bindPort,  java.util.Collection<String> members) throws Exception {
        // 1. Initialize PQC Cryptography (WolfSSL)
        initWolfSsl();

        // 2. Configure the Secure TCP Transport
        TCP tcp = new TCP();
        tcp.setBindPort(bindPort);
        tcp.tls(new TLS()
                .enabled(true)
                .setSSLContext(createPqcContext()));

        // 3. Define the Raft Protocol
        RAFT raft = new RAFT()
                .members(members)
                .raftId(nodeId);

        // 4. Build the Stack
        this.channel = new JChannel(
                tcp,
                new TCPPING().initialHosts(Arrays.asList(
                        new InetSocketAddress("127.0.0.1", 11111),
                        new InetSocketAddress("127.0.0.1", 11112),
                        new InetSocketAddress("127.0.0.1", 11113)
                )),
                new MERGE3(),
                new FD_SOCK(),
                new FD_ALL3(),
                new VERIFY_SUSPECT(),
                new NAKACK2(),
                new UNICAST3(),
                new STABLE(),
                new GMS(),
                new ELECTION(),
                raft
        );

        // 5. Initialize the Replicated State Machine block
        // This block wraps the channel and provides a Map-like API
        this.rsm = new ReplicatedStateMachine<>(this.channel);

        // 6. Connect to the cluster
        this.channel.connect("pqc-raft-map-cluster");
        System.out.println("\n🔐 Node [" + nodeId + "] online. Cluster secured with Dilithium/ECC.");
    }

    private void initWolfSsl() {
        System.load("/home/vonasmic/diplomka/one-time-pad-keychain/wolfssljni/lib/libwolfssljni.so");
        System.setProperty("com.wolfssl.jsse.altPrivateKey", new File("../tls_usb_test/certs/dilithium-server.priv").getAbsolutePath());
        System.setProperty("com.wolfssl.jsse.expectedSigSpecs", "both");
        Security.insertProviderAt(new com.wolfssl.provider.jsse.WolfSSLProvider(), 1);
    }

    private SSLContext createPqcContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(P12_FILE)) {
            ks.load(fis, P12_PASS);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, P12_PASS);
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "wolfJSSE");
        sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
        return sslContext;
    }

    public void startCli() {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("> ");
            String line = scanner.nextLine();
            String[] args = line.split(" ");

            try {
                if (args[0].equals("put")) {
                    rsm.put(args[1], args[2]);
                    System.out.println("Replicated.");
                } else if (args[0].equals("get")) {
                    System.out.println("Value: " + rsm.get(args[1]));
                } else if (args[0].equals("list")) {
                    System.out.println("All data: " + rsm);
                }
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args) throws Exception {
        String id = args.length > 0 ? args[0] : "nodeA";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 11111;
        new PqcRaftMap(id, port, List.of(new String[]{"nodeA", "nodeB", "nodeC"})).startCli();
    }
}