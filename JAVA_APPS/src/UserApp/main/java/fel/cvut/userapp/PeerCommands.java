package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeManage;

import java.util.Locale;
import java.util.Scanner;

/**
 * PEER ADD / REMOVE / LIST console flows.
 */
final class PeerCommands {

    private static final String HASH_PROMPT = "Peer cert hash (96 hex): ";

    private PeerCommands() {
    }

    static void run(Scanner sc, ChipService chip, String command) throws Exception {
        String afterPeer = command.length() > 4 ? command.substring(4).strip() : "";
        if (afterPeer.isEmpty()) {
            afterPeer = ConsoleIo.readLine(sc, "PEER [ADD/REMOVE/LIST]: ");
            if (afterPeer == null) {
                return;
            }
            afterPeer = afterPeer.strip();
        }
        String sub = afterPeer.toUpperCase(Locale.ROOT);
        if (sub.equals("LIST") || sub.equals("L")) {
            String list = chip.peerList();
            if (list == null || list.isBlank()) {
                System.out.println("(no peers)");
            } else {
                System.out.println(list);
            }
            return;
        }
        if (sub.equals("REMOVE") || sub.equals("R") || sub.startsWith("REMOVE")) {
            remove(sc, chip, afterPeer);
            return;
        }
        if (sub.equals("ADD") || sub.equals("A") || sub.startsWith("ADD")) {
            add(sc, chip, afterPeer);
            return;
        }
        System.err.println("Unknown PEER subcommand. Use ADD, REMOVE, or LIST.");
    }

    private static void remove(Scanner sc, ChipService chip, String afterPeer) throws Exception {
        String name = nickname(sc, afterPeer, "REMOVE");
        if (name == null) {
            return;
        }
        String pin = ConsoleIo.readPin(sc);
        if (pin == null) {
            return;
        }
        SeManage.Reply r = chip.peerRemove(pin, name);
        if (!r.ok()) {
            System.err.println("PEER REMOVE failed: " + r.msg());
            return;
        }
        System.out.println("OK PEER REMOVE " + name);
    }

    private static void add(Scanner sc, ChipService chip, String afterPeer) throws Exception {
        String name = nickname(sc, afterPeer, "ADD");
        if (name == null) {
            return;
        }
        String hashInput = ConsoleIo.readRequired(sc, HASH_PROMPT);
        if (hashInput == null) {
            return;
        }
        String hash;
        try {
            hash = PeerCertHash.parseHashHex(hashInput);
        } catch (IllegalArgumentException ex) {
            System.err.println(ex.getMessage());
            return;
        }
        String pin = ConsoleIo.readPin(sc);
        if (pin == null) {
            return;
        }
        SeManage.Reply r = chip.peerAdd(pin, name, SeBytes.fromHex(hash));
        if (!r.ok()) {
            System.err.println("PEER ADD failed: " + r.msg());
            return;
        }
        System.out.println("OK PEER ADD " + name);
    }

    private static String nickname(Scanner sc, String afterPeer, String verb) {
        String name = peerArg(afterPeer, verb);
        if (name.isEmpty()) {
            name = ConsoleIo.readRequired(sc, "Nickname: ");
            if (name == null) {
                return null;
            }
        }
        if (!PeerCertHash.validNickname(name)) {
            System.err.println("Nickname must be 1-16 of [A-Za-z0-9_.-].");
            return null;
        }
        return name;
    }

    /** Remainder after {@code ADD}/{@code REMOVE}, preserving nickname case. */
    private static String peerArg(String afterPeer, String verb) {
        if (afterPeer.length() <= verb.length()) {
            return "";
        }
        if (!afterPeer.regionMatches(true, 0, verb, 0, verb.length())) {
            return "";
        }
        return afterPeer.substring(verb.length()).strip();
    }
}
