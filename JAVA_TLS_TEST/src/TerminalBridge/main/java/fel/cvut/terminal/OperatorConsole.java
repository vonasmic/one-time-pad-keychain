package fel.cvut.terminal;

import java.util.List;

/**
 * Abstraction over "ask a human operator" interactions a node needs during a client request:
 * picking a target client/SAE, confirming destructive actions, and showing status messages
 * such as transmission outcome.
 *
 * <p>{@link LocalOperatorConsole} answers these locally via stdin (used by the standalone
 * terminal app). A node instead uses a remote implementation that forwards requests to whichever
 * terminal app is currently connected, over the same TLS configuration nodes use to talk to each
 * other.
 */
public interface OperatorConsole {

    ClientSelector.Selection selectTarget(
            List<ClientSelector.LabeledOption> clients, List<ClientSelector.LabeledOption> saes
    ) throws Exception;

    boolean confirmDeletion(String message) throws Exception;

    void showMessage(String message) throws Exception;
}
