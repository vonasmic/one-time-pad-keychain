package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeManage;
import fel.cvut.terminal.AppLogging;

import java.util.Locale;
import java.util.Scanner;

/**
 * PEER ADD / REMOVE / LIST / CARD and CLIENT INFO console flows.
 */
final class PeerCommands {

    private static final String HASH_PROMPT = "Peer cert hash (96 hex): ";
    private static final String PAD_PROMPT = "Tropic pad: ";
    private static final String NICK_FOR_PEER_PROMPT = "Nickname the other side should store: ";

    private PeerCommands() {
    }

    static void run(Scanner sc, ChipService chip, String command) throws Exception {
        String afterPeer = command.length() > 4 ? command.substring(4).strip() : "";
        if (afterPeer.isEmpty()) {
            afterPeer = ConsoleIo.readLine(sc, "PEER [ADD/REMOVE/LIST/CARD]: ");
            if (afterPeer == null) {
                return;
            }
            afterPeer = afterPeer.strip();
        }
        String sub = afterPeer.toUpperCase(Locale.ROOT);
        if (sub.equals("LIST") || sub.equals("L")) {
            String list = chip.peerList();
            if (list == null || list.isBlank()) {
                ConsoleStyle.note("(no peers)");
            } else {
                ConsoleStyle.reply(list);
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
        if (sub.equals("CARD") || sub.startsWith("CARD")) {
            card(sc, chip, afterPeer);
            return;
        }
        ConsoleStyle.err("Unknown PEER subcommand. Use PEER ADD, PEER REMOVE, PEER LIST, or PEER CARD.");
    }

    static void clientInfo(Scanner sc, ChipService chip, String command) throws Exception {
        String after = remainderAfter(command, "CLIENT INFO");
        String name = after.isEmpty()
                ? ConsoleIo.readRequired(sc, NICK_FOR_PEER_PROMPT)
                : after;
        if (name == null) {
            return;
        }
        if (!PeerCertHash.validNickname(name)) {
            ConsoleStyle.err("Nickname must be 1-16 of [A-Za-z0-9_.-].");
            return;
        }
        Identity identity = readLocalIdentity(chip);
        if (identity == null) {
            return;
        }
        AppLogging.terminalOut().println("Name: " + name);
        AppLogging.terminalOut().println("Hash: " + identity.hashHex);
        AppLogging.terminalOut().println("Tropic pad: " + identity.padPlain);
    }

    private static void card(Scanner sc, ChipService chip, String afterPeer) throws Exception {
        String name = nickname(sc, afterPeer, "CARD", NICK_FOR_PEER_PROMPT);
        if (name == null) {
            return;
        }
        Identity identity = readLocalIdentity(chip);
        if (identity == null) {
            return;
        }
        AppLogging.terminalOut().println("PEER ADD");
        AppLogging.terminalOut().println(name);
        AppLogging.terminalOut().println(identity.hashHex);
        AppLogging.terminalOut().println(identity.padPlain);
    }

    private static void remove(Scanner sc, ChipService chip, String afterPeer) throws Exception {
        String name = nickname(sc, afterPeer, "REMOVE", "Nickname: ");
        if (name == null) {
            return;
        }
        SeManage.Reply r = chip.peerRemove(name);
        if (!r.ok()) {
            ConsoleStyle.err("PEER REMOVE failed: " + r.msg());
            return;
        }
        ConsoleStyle.ok("OK PEER REMOVE " + name);
    }

    private static void add(Scanner sc, ChipService chip, String afterPeer) throws Exception {
        String name = nickname(sc, afterPeer, "ADD", "Nickname: ");
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
            ConsoleStyle.err(ex.getMessage());
            return;
        }
        String padInput = ConsoleIo.readRequired(sc, PAD_PROMPT);
        if (padInput == null) {
            return;
        }
        int padPlain;
        try {
            padPlain = parsePadPlain(padInput);
        } catch (IllegalArgumentException ex) {
            ConsoleStyle.err(ex.getMessage());
            return;
        }
        SeManage.Reply r = chip.peerAdd(name, SeBytes.fromHex(hash), padPlain);
        if (!r.ok()) {
            ConsoleStyle.err("PEER ADD failed: " + r.msg());
            return;
        }
        ConsoleStyle.ok("OK PEER ADD " + name);
    }

    private static Identity readLocalIdentity(ChipService chip) throws Exception {
        String hash;
        try {
            hash = PeerCertHash.parseHashHex(chip.clientHashHex().replaceAll("\\s+", ""));
        } catch (IllegalArgumentException ex) {
            ConsoleStyle.err("CLIENT HASH failed: " + ex.getMessage());
            return null;
        }
        int padPlain;
        try {
            padPlain = parsePadPlain(chip.tropicPadLen());
        } catch (IllegalArgumentException ex) {
            ConsoleStyle.err("TROPIC PAD LEN failed: " + ex.getMessage());
            return null;
        }
        return new Identity(hash, padPlain);
    }

    private static String nickname(Scanner sc, String afterPeer, String verb, String prompt) {
        String name = peerArg(afterPeer, verb);
        if (name.isEmpty()) {
            name = ConsoleIo.readRequired(sc, prompt);
            if (name == null) {
                return null;
            }
        }
        if (!PeerCertHash.validNickname(name)) {
            ConsoleStyle.err("Nickname must be 1-16 of [A-Za-z0-9_.-].");
            return null;
        }
        return name;
    }

    /** Remainder after {@code ADD}/{@code REMOVE}/{@code CARD}, preserving nickname case. */
    private static String peerArg(String afterPeer, String verb) {
        if (afterPeer.length() <= verb.length()) {
            return "";
        }
        if (!afterPeer.regionMatches(true, 0, verb, 0, verb.length())) {
            return "";
        }
        return afterPeer.substring(verb.length()).strip();
    }

    private static String remainderAfter(String command, String prefix) {
        if (command.length() <= prefix.length()) {
            return "";
        }
        if (!command.regionMatches(true, 0, prefix, 0, prefix.length())) {
            return "";
        }
        return command.substring(prefix.length()).strip();
    }

    static int parsePadPlain(String raw) {
        String line = firstLine(raw);
        if (line.isEmpty() || ConsoleStyle.isFailure(line) || line.equalsIgnoreCase("empty")) {
            throw new IllegalArgumentException("expected a positive decimal Tropic pad length");
        }
        int value;
        try {
            value = Integer.parseInt(line);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Tropic pad length must be a decimal integer");
        }
        if (value < 1 || value > 0xFFFF) {
            throw new IllegalArgumentException("Tropic pad length must be 1..65535");
        }
        return value;
    }

    private static String firstLine(String reply) {
        if (reply == null) {
            return "";
        }
        return reply.strip().lines()
                .map(String::strip)
                .filter(s -> !s.isEmpty())
                .findFirst()
                .orElse("");
    }

    private record Identity(String hashHex, int padPlain) {
    }
}
