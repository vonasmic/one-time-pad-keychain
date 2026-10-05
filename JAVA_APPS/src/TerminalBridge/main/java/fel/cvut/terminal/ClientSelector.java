package fel.cvut.terminal;

import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Terminal selection menu for target client and SAE.
 */
public final class ClientSelector {

    private ClientSelector() {
    }

    public static Selection select(List<LabeledOption> clients, List<LabeledOption> saes) {
        List<LabeledOption> orderedClients = normalizeOptions(clients, "clients");
        List<LabeledOption> orderedSaes = normalizeOptions(saes, "saes");

        int saeSelection = promptChoice(
                "Select target SAE:", orderedSaes, ClientSelector::formatSaeOptionLabel, "Enter SAE number: ");
        int clientSelection = promptChoice(
                "Select target client:", orderedClients, LabeledOption::label, "Enter client number: ");

        return new Selection(
                orderedClients.get(clientSelection - 1).id(),
                orderedSaes.get(saeSelection - 1).id());
    }

    private static int promptChoice(
            String title, List<LabeledOption> options, Function<LabeledOption, String> labeler, String prompt
    ) {
        System.out.println(title);
        for (int index = 0; index < options.size(); index++) {
            System.out.println((index + 1) + ") " + labeler.apply(options.get(index)));
        }
        return readSelection(options.size(), prompt);
    }

    private static String formatSaeOptionLabel(LabeledOption option) {
        String id = option.id();
        String label = option.label();
        if (label.isEmpty() || label.equals(id)) {
            return id;
        }
        return label + " (" + id + ")";
    }

    private static int readSelection(int limit, String prompt) {
        while (true) {
            System.out.print(prompt);
            String rawValue = TerminalOutput.STDIN.nextLine();
            int value;
            try {
                value = Integer.parseInt(rawValue.trim());
            } catch (NumberFormatException ex) {
                System.out.println("Invalid input. Enter a number between 1 and " + limit + ".");
                continue;
            }

            if (value >= 1 && value <= limit) {
                return value;
            }
            System.out.println("Selection out of range. Enter a number between 1 and " + limit + ".");
        }
    }

    private static List<LabeledOption> normalizeOptions(List<LabeledOption> options, String fieldName) {
        Objects.requireNonNull(options, fieldName + " must not be null");
        List<LabeledOption> result = options.stream()
                .filter(Objects::nonNull)
                .map(option -> {
                    String id = Objects.toString(option.id(), "").trim();
                    if (id.isEmpty()) {
                        return null;
                    }
                    String label = Objects.toString(option.label(), "").trim();
                    if (label.isEmpty()) {
                        label = id;
                    }
                    return new LabeledOption(id, label);
                })
                .filter(Objects::nonNull)
                .toList();
        if (result.isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must contain at least one option.");
        }
        return result;
    }

    public record LabeledOption(String id, String label) {
    }

    public record Selection(String clientId, String saeId) {
    }
}
