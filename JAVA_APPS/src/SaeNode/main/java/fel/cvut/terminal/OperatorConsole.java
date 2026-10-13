package fel.cvut.terminal;

import java.util.List;

/**
 * Ask a human operator during a client request: pick a target client/SAE, confirm
 * destructive actions, and show status. Implemented by this process's stdin.
 */
public interface OperatorConsole {

    ClientSelector.Selection selectTarget(
            List<ClientSelector.LabeledOption> clients, List<ClientSelector.LabeledOption> saes
    ) throws Exception;

    boolean confirmDeletion(String message) throws Exception;

    void showMessage(String message) throws Exception;
}
