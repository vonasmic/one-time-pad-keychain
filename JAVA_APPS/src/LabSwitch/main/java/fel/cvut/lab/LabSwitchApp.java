package fel.cvut.lab;

import java.util.Locale;
import java.util.Scanner;

/**
 * Lab-only CLI that writes {@link LabSwitch}'s JSON file.
 *
 * <pre>{@code
 *   USER — both UserApp panes own USB (ENCRYPT / DECRYPT / bring-up)
 *   SAE  — both SaeNode panes own USB (PROVISION); lab-run restarts each node
 * }</pre>
 *
 * <p>Starts at {@code USER} so {@code se_host} bring-up can finish before any SAE connect.
 * Keychains run in parallel ({@code userapp-1}/{@code node-1} and
 * {@code userapp-2}/{@code node-2}); there is no CL 1 / CL 2 switch.
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
                System.out.print("Lab [USER / SAE / status / quit]: ");
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
        System.out.println("[lab] " + lab.path() + " → owner=" + state.mode());
        state.nodes().forEach((id, n) -> System.out.println(
                "[lab] " + id + " serial=" + n.serialPort()));
        if (state.holdsTerminal()) {
            System.out.println("[lab] SAE owns USB on both clients"
                    + " (node-1/2 restart with the serial port; userapp-1/2 stop)");
        } else {
            System.out.println("[lab] USER owns USB on both clients"
                    + " (userapp-1/2 start; node-1/2 restart with USB off)");
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
