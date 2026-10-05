package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeManage;
import fel.cvut.se.SecureOtp;

import java.util.Scanner;

/**
 * Shared stdin prompts for the UserApp console.
 */
final class ConsoleIo {

    private ConsoleIo() {
    }

    static String readPin(Scanner sc) {
        while (true) {
            System.out.print(ChipInit.TROPIC_PIN_PROMPT);
            if (!sc.hasNextLine()) {
                return null;
            }
            String pin = sc.nextLine();
            if (SeManage.pinOk(pin)) {
                return pin;
            }
            System.err.println("Tropic PIN must be 8 to 16 printable ASCII characters.");
        }
    }

    static String readRequired(Scanner sc, String prompt) {
        System.out.print(prompt);
        if (!sc.hasNextLine()) {
            return null;
        }
        String value = sc.nextLine().strip();
        if (value.isEmpty()) {
            System.err.println("Value must not be empty.");
            return null;
        }
        return value;
    }

    static String readLine(Scanner sc, String prompt) {
        System.out.print(prompt);
        if (!sc.hasNextLine()) {
            return null;
        }
        return sc.nextLine();
    }

    static byte[] readEncryptReplyHex(Scanner sc, byte[] lastEncryptReply) {
        System.out.print("Encrypt reply hex (empty = last): ");
        if (!sc.hasNextLine()) {
            return null;
        }
        String line = sc.nextLine().trim();
        if (line.isEmpty()) {
            if (lastEncryptReply == null || lastEncryptReply.length == 0) {
                System.err.println("No previous encrypt reply. Paste the hex from ENCRYPT.");
                return null;
            }
            return lastEncryptReply;
        }
        try {
            byte[] raw = SeBytes.fromHex(line);
            SecureOtp.decodeEncryptReply(raw);
            return raw;
        } catch (Exception e) {
            System.err.println("Invalid encrypt reply: " + e.getMessage());
            return null;
        }
    }
}
