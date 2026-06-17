package fel.cvut.terminal;

import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * Generic terminal output helper.
 */
public final class TerminalOutput {
    private static final Scanner SCANNER = new Scanner(System.in, StandardCharsets.UTF_8);

    private TerminalOutput() {
    }

    public static void printString(String value) {
        if (value == null) {
            return;
        }
        System.out.println(value);
    }

    public static boolean promptDeletion(String message) {
        printString(message);
        while (true) {
            System.out.println("Delete records and start anew? (y/n)");
            String input = SCANNER.nextLine().trim();
            if ("y".equalsIgnoreCase(input) || "yes".equalsIgnoreCase(input)) {
                return true;
            }
            if ("n".equalsIgnoreCase(input) || "no".equalsIgnoreCase(input)) {
                return false;
            }
            System.out.println("Invalid choice. Enter y or n.");
        }
    }
}

