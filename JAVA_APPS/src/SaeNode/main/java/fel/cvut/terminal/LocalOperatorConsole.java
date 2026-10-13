package fel.cvut.terminal;

import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * {@link OperatorConsole} on this process's stdin/stdout. Prompts share one lock
 * so SELECT, CONFIRM, NOTIFY, and "provision another?" cannot interleave.
 */
public final class LocalOperatorConsole implements OperatorConsole {

    private final ReentrantLock lock = new ReentrantLock();

    @Override
    public ClientSelector.Selection selectTarget(
            List<ClientSelector.LabeledOption> clients, List<ClientSelector.LabeledOption> saes
    ) {
        lock.lock();
        try {
            return ClientSelector.select(clients, saes);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean confirmDeletion(String message) {
        return promptYesNo(message);
    }

    @Override
    public void showMessage(String message) {
        lock.lock();
        try {
            if (message != null) {
                AppLogging.terminalOut().println(message);
            }
        } finally {
            lock.unlock();
        }
    }

    public boolean promptYesNo(String message) {
        lock.lock();
        try {
            return TerminalOutput.promptYesNo(message);
        } finally {
            lock.unlock();
        }
    }
}
