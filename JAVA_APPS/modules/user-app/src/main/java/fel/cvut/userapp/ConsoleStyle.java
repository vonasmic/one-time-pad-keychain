package fel.cvut.userapp;

import fel.cvut.terminal.AppLogging;

import java.io.FileDescriptor;
import java.util.Locale;

/**
 * Semantic terminal styling for the UserApp console.
 *
 * <p>Color marks meaning only: green for a completed action, red for a failure,
 * yellow for a warning, cyan for a hex payload. Group labels and the prompt use
 * bold (and blue, when color is on) so the command list stays a landmark under
 * the last result. Standard ANSI colors follow the terminal theme.
 *
 * <p>Color is off when the stream is not a terminal, {@code TERM=dumb}, or
 * {@code NO_COLOR} / {@code USERAPP_NO_COLOR} is non-empty. {@code FORCE_COLOR}
 * (any value other than {@code 0} or {@code false}) turns color back on, including
 * over {@code NO_COLOR}.
 * Bold and dim stay available when {@code NO_COLOR} is set on a terminal.
 */
final class ConsoleStyle {

    static final int COMMAND_INTERFACE_VERSION = 2;

    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String DIM = "\u001B[2m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String BLUE = "\u001B[34m";
    private static final String CYAN = "\u001B[36m";

    private static final int LABEL_WIDTH = 12;
    private static final int HELP_WIDTH = 20;
    private static final String RULE = "─".repeat(44);

    private static final ConsoleStyle OUT = detect(FileDescriptor.out, 1);
    private static final ConsoleStyle ERR = detect(FileDescriptor.err, 2);

    private final boolean color;
    private final boolean style;

    private ConsoleStyle(boolean color, boolean style) {
        this.color = color;
        this.style = style;
    }

    static void rule() {
        AppLogging.terminalOut().println(OUT.paint(RULE, DIM, false, false));
    }

    static void menuTitle(String title) {
        AppLogging.terminalOut().println(OUT.paint(title, null, true, false));
    }

    static void menuRow(String group, String commands) {
        AppLogging.terminalOut().print(OUT.paint(String.format("%-" + LABEL_WIDTH + "s", group), BLUE, true, false));
        AppLogging.terminalOut().println(commands);
    }

    static void prompt(String text) {
        AppLogging.terminalOut().print(OUT.paint(text, null, true, false));
        AppLogging.terminalOut().flush();
    }

    static void section(String name) {
        AppLogging.terminalOut().println(OUT.paint(name, BLUE, true, false));
    }

    static void helpItem(String command, String explanation) {
        AppLogging.terminalOut().print("  ");
        AppLogging.terminalOut().print(OUT.paint(String.format("%-" + HELP_WIDTH + "s", command), null, true, false));
        AppLogging.terminalOut().println(OUT.paint(explanation, DIM, false, true));
    }

    static void note(String text) {
        AppLogging.terminalOut().println(OUT.paint(text, DIM, false, true));
    }

    /** Completed action. The line stays on stdout. */
    static void ok(String text) {
        AppLogging.terminalOut().println(OUT.paint(text, GREEN, true, false));
    }

    /**
     * Success text with hex lines in cyan so the payload is distinct from the
     * status sentence above it.
     */
    static void okBlock(String text) {
        if (text == null || text.isBlank()) {
            return;
        }
        for (String line : text.split("\n", -1)) {
            if (line.isEmpty()) {
                AppLogging.terminalOut().println();
            } else if (isHexLine(line)) {
                data(line);
            } else if (line.toLowerCase(Locale.ROOT).contains("unavailable")) {
                warn(line);
            } else {
                ok(line);
            }
        }
    }

    /** Machine payload (hex). Not a success or a failure by itself. */
    static void data(String text) {
        AppLogging.terminalOut().println(OUT.paint(text, CYAN, false, false));
    }

    static void err(String text) {
        AppLogging.terminalErr().println(ERR.paint(text, RED, false, false));
    }

    static void warn(String text) {
        AppLogging.terminalErr().println(ERR.paint(text, YELLOW, false, false));
    }

    /** Chip console reply: red when it failed, cyan when it is hex, otherwise plain. */
    static void reply(String reply) {
        if (reply == null || reply.isBlank()) {
            note("(no reply)");
            return;
        }
        String first = reply.strip().lines().findFirst().orElse("");
        if (isFailure(first)) {
            AppLogging.terminalOut().println(OUT.paint(reply, RED, false, false));
            return;
        }
        if (isHexBlock(reply)) {
            data(reply.strip());
            return;
        }
        AppLogging.terminalOut().println(reply);
    }

    static boolean isFailure(String firstLine) {
        if (firstLine == null) {
            return false;
        }
        String lower = firstLine.strip().toLowerCase(Locale.ROOT);
        return lower.equals("failed")
                || lower.startsWith("failed ")
                || lower.startsWith("failed:")
                || lower.startsWith("error");
    }

    static boolean isHexBlock(String reply) {
        boolean any = false;
        for (String line : reply.strip().split("\n", -1)) {
            if (line.isBlank()) {
                continue;
            }
            if (!isHexLine(line)) {
                return false;
            }
            any = true;
        }
        return any;
    }

    static String decorate(String text, String colorCode, boolean bold, boolean dim,
                           boolean colorOn, boolean styleOn) {
        if (text == null || text.isEmpty()) {
            return text == null ? "" : text;
        }
        String open = open(colorCode, bold, dim, colorOn, styleOn);
        if (open.isEmpty()) {
            return text;
        }
        return open + text + RESET;
    }

    private String paint(String text, String colorCode, boolean bold, boolean dim) {
        return decorate(text, colorCode, bold, dim, color, style);
    }

    private static String open(String colorCode, boolean bold, boolean dim,
                               boolean colorOn, boolean styleOn) {
        String open = "";
        if (styleOn && bold) {
            open += BOLD;
        }
        if (styleOn && dim) {
            open += DIM;
        }
        if (colorOn && colorCode != null) {
            open += colorCode;
        }
        return open;
    }

    private static boolean isHexLine(String line) {
        String hex = line.strip();
        return hex.length() >= 8 && hex.matches("[0-9a-fA-F]+");
    }

    private static ConsoleStyle detect(FileDescriptor fd, int posixFd) {
        if (forcedOff()) {
            return new ConsoleStyle(false, false);
        }
        String term = System.getenv("TERM");
        boolean dumb = term != null && term.equalsIgnoreCase("dumb");
        boolean forced = forceColor();
        if (forced) {
            return new ConsoleStyle(true, true);
        }
        if (dumb || !isTerminal(fd, posixFd)) {
            return new ConsoleStyle(false, false);
        }
        return new ConsoleStyle(!noColorRequested(), true);
    }

    /** {@code FORCE_COLOR=0} or {@code false} disables color even on a terminal. */
    private static boolean forcedOff() {
        String force = System.getenv("FORCE_COLOR");
        if (force == null) {
            return false;
        }
        String value = force.trim();
        return value.equals("0") || value.equalsIgnoreCase("false");
    }

    private static boolean forceColor() {
        String force = System.getenv("FORCE_COLOR");
        if (force == null) {
            return false;
        }
        String value = force.trim();
        return !value.equals("0") && !value.equalsIgnoreCase("false");
    }

    /** {@code NO_COLOR} and {@code USERAPP_NO_COLOR} disable color when non-empty. */
    private static boolean noColorRequested() {
        return nonEmpty(System.getenv("NO_COLOR")) || nonEmpty(System.getenv("USERAPP_NO_COLOR"));
    }

    private static boolean nonEmpty(String value) {
        return value != null && !value.isEmpty();
    }

    private static boolean isTerminal(FileDescriptor fd, int posixFd) {
        try {
            ProcessBuilder builder = new ProcessBuilder("test", "-t", Integer.toString(posixFd));
            if (fd == FileDescriptor.out) {
                builder.redirectOutput(ProcessBuilder.Redirect.INHERIT);
                builder.redirectError(ProcessBuilder.Redirect.DISCARD);
            } else {
                builder.redirectOutput(ProcessBuilder.Redirect.DISCARD);
                builder.redirectError(ProcessBuilder.Redirect.INHERIT);
            }
            builder.redirectInput(ProcessBuilder.Redirect.DISCARD);
            return builder.start().waitFor() == 0;
        } catch (Exception ignored) {
            return System.console() != null;
        }
    }
}
