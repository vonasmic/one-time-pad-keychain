package fel.cvut.lab;

import java.util.Locale;
import java.util.Scanner;

/**
 * Lab-only CLI that writes {@link LabSwitch}'s JSON file.
 *
 * <pre>{@code
 *   USER      — UserApp owns USB (keep selected client)
 *   SAE       — Terminal owns USB (keep selected client)
 *   CL 1  — keychain + SAE 1  (/tmp/ttyACM-se1 → node-1)
 *   CL 2  — keychain + SAE 2  (/tmp/ttyACM-se2 → node-2)
 * }</pre>
 *
 * <p>Starts at {@code USER} + CL 1 so {@code se_host} bring-up can finish before any SAE connect.
 */
public final class LabSwitchApp {

    private LabSwitchApp() {
    }

    public static void main(String[] args) {
        LabSwitch lab = LabSwitch.open(pathFromEnv());
        if (args.length > 0) {
            LabSwitch.State state = lab.apply(String.join(" ", args));
            printState(lab, state);
            return;
        }
        interactive(lab);
    }

    private static void interactive(LabSwitch lab) {
        printState(lab, lab.read());
        try (Scanner sc = new Scanner(System.in)) {
            while (true) {
                System.out.print("Lab [USER / SAE / CL 1 / CL 2 / status / quit]: ");
                if (!sc.hasNextLine()) {
                    return;
                }
                String line = sc.nextLine().trim();
                if (line.isEmpty()) {
                    continue;
                }
                String upper = line.toUpperCase(Locale.ROOT);
                if (upper.equals("QUIT") || upper.equals("Q") || upper.equals("EXIT")) {
                    return;
                }
                if (upper.equals("STATUS") || upper.equals("S") || upper.equals("?")) {
                    printState(lab, lab.read());
                    continue;
                }
                try {
                    printState(lab, lab.apply(line));
                } catch (IllegalArgumentException e) {
                    System.err.println(e.getMessage());
                }
            }
        }
    }

    private static void printState(LabSwitch lab, LabSwitch.State state) {
        System.out.println("[lab] " + lab.path() + " → owner=" + state.mode()
                + " client=" + state.clientLabel()
                + " (" + state.saeId() + ")"
                + " serial=" + state.serialPort());
        state.nodes().forEach((id, n) -> System.out.println(
                "[lab] " + (LabSwitch.ID_CLIENT2.equals(id) ? "CL 2" : "CL 1")
                        + " (" + (LabSwitch.ID_CLIENT2.equals(id) ? "SAE 2" : "SAE 1") + ")"
                        + " serial=" + n.serialPort()
                        + " → " + n.host()
                        + " native=" + n.nativePort()
                        + " terminal=" + n.terminalPort()));
        if (state.holdsTerminal()) {
            LabSwitch.Node n = state.node();
            System.out.println("[lab] SAE owns USB → " + state.saeId()
                    + " / " + state.clientLabel()
                    + " (" + n.host() + " native=" + n.nativePort()
                    + " terminal=" + n.terminalPort() + ")");
        } else {
            System.out.println("[lab] USER owns USB (" + state.clientLabel()
                    + " / " + state.saeId()
                    + " ENCRYPT/DECRYPT / se_host bring-up)");
        }
    }

    private static java.nio.file.Path pathFromEnv() {
        String file = System.getenv("USB_LAB_FILE");
        if (file == null || file.isBlank()) {
            return LabSwitch.DEFAULT_PATH;
        }
        return java.nio.file.Path.of(file.trim());
    }
}
