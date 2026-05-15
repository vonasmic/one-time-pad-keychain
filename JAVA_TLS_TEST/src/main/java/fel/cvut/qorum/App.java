package fel.cvut.qorum;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import java.security.Security;
import java.util.Scanner;

public class App {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());

        String nodeId = (args.length > 0) ? args[0] : "Alice";

        System.out.println("Starting Node: " + nodeId);

        try (SecureInfinispanNode node = new SecureInfinispanNode(nodeId)) {
            Scanner scanner = new Scanner(System.in);

            System.out.println("Node " + nodeId + " is online. Commands: 'write', 'read', 'exit'");

            label:
            while (true) {
                System.out.print("> ");
                String command = scanner.nextLine().toLowerCase();

                switch (command) {
                    case "exit":
                        break label;
                    case "write": {
                        System.out.print("Enter hash1: ");
                        String hash1 = scanner.nextLine();
                        System.out.print("Enter hash2: ");
                        String hash2 = scanner.nextLine();
                        System.out.print("Enter JSON Value: ");
                        String v = scanner.nextLine();

                        node.secureWrite(new ClientRecord(hash1, hash2, v, nodeId));
                        break;
                    }
                    case "read": {
                        System.out.print("Enter hash1: ");
                        String hash1 = scanner.nextLine();
                        System.out.print("Enter hash2: ");
                        String hash2 = scanner.nextLine();

                        String result = node.secureRead(new RecordKey(hash1, hash2));
                        System.out.println("Result: " + result);
                        break;
                    }
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
