package fel.cvut.terminal;

import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * Shared stdin helpers for the local operator UI.
 */
public final class TerminalOutput {

    static final Scanner STDIN = new Scanner(System.in, StandardCharsets.UTF_8);

    private TerminalOutput() {
    }

    public static boolean promptYesNo(String message) {
        AppLogging.terminalOut().println(message);
        while (true) {
            AppLogging.terminalOut().print("[y/n] ");
            String input = STDIN.nextLine().trim();
            if ("y".equalsIgnoreCase(input) || "yes".equalsIgnoreCase(input)) {
                return true;
            }
            if ("n".equalsIgnoreCase(input) || "no".equalsIgnoreCase(input)) {
                return false;
            }
            AppLogging.terminalOut().println("Invalid choice. Enter y or n.");
        }
    }
}
