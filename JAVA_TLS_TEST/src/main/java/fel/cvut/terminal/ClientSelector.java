package fel.cvut.terminal;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;

/**
 * Terminal selection menu for target client and SAE.
 */
public final class ClientSelector {

    private ClientSelector() {
    }

    public static Selection select(List<LabeledOption> clients, List<LabeledOption> saes) {
        List<LabeledOption> orderedClients = normalizeOptions(clients, "clients");
        List<LabeledOption> orderedSaes = normalizeOptions(saes, "saes");
        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);

        System.out.println("Select target SAE:");
        for (int index = 0; index < orderedSaes.size(); index++) {
            System.out.println((index + 1) + ") " + formatSaeOptionLabel(orderedSaes.get(index)));
        }
        int saeSelection = readSelection(scanner, orderedSaes.size(), "Enter SAE number: ");

        System.out.println("Select target client:");
        for (int index = 0; index < orderedClients.size(); index++) {
            System.out.println((index + 1) + ") " + orderedClients.get(index).label());
        }
        int clientSelection = readSelection(scanner, orderedClients.size(), "Enter client number: ");

        String selectedClientId = orderedClients.get(clientSelection - 1).id();
        String selectedSaeId = orderedSaes.get(saeSelection - 1).id();
        return new Selection(selectedClientId, selectedSaeId);
    }

    private static String formatSaeOptionLabel(LabeledOption option) {
        String id = option.id();
        String label = option.label();
        if (label.isEmpty() || label.equals(id)) {
            return id;
        }
        return label + " (" + id + ")";
    }

    private static int readSelection(Scanner scanner, int limit, String prompt) {
        while (true) {
            System.out.print(prompt);
            String rawValue = scanner.nextLine();
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
