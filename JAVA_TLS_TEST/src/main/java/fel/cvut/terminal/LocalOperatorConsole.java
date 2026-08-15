package fel.cvut.terminal;

import java.util.List;

/** {@link OperatorConsole} backed by this process's own stdin/stdout — used by the terminal app. */
public final class LocalOperatorConsole implements OperatorConsole {

    @Override
    public ClientSelector.Selection selectTarget(
            List<ClientSelector.LabeledOption> clients, List<ClientSelector.LabeledOption> saes
    ) {
        return ClientSelector.select(clients, saes);
    }

    @Override
    public boolean confirmDeletion(String message) {
        return TerminalOutput.promptDeletion(message);
    }

    @Override
    public void showMessage(String message) {
        TerminalOutput.printString(message);
    }
}
