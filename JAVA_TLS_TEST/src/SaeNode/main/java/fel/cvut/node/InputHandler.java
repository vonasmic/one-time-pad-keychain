package fel.cvut.node;

import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.se.SeSessionUplink;
import fel.cvut.terminal.ClientSelector;
import fel.cvut.terminal.OperatorConsole;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Verifies the SE LV uplink and drives operator target selection.
 */
public class InputHandler {

    public record OperatorSelection(ClientRecord clientRecord, SeSessionUplink uplink) {
        public OperatorSelection {
            Objects.requireNonNull(clientRecord, "clientRecord must not be null");
            Objects.requireNonNull(uplink, "uplink must not be null");
        }
    }

    public OperatorSelection handleInput(
            SSLSocket socket,
            byte[] exporter,
            List<RmiManager.SaeNode> saeNodes,
            OperatorConsole operatorConsole
    ) throws IOException {
        Objects.requireNonNull(socket, "socket must not be null");
        Objects.requireNonNull(exporter, "exporter must not be null");
        Objects.requireNonNull(operatorConsole, "operatorConsole must not be null");

        SeSessionUplink uplink = SeSessionUplink.readAndVerify(socket, exporter);
        return selectForUplink(uplink, saeNodes, operatorConsole);
    }

    /**
     * Repeats SAE/client selection against an already-verified uplink (device stays connected).
     */
    public OperatorSelection selectForUplink(
            SeSessionUplink uplink,
            List<RmiManager.SaeNode> saeNodes,
            OperatorConsole operatorConsole
    ) throws IOException {
        Objects.requireNonNull(uplink, "uplink must not be null");
        Objects.requireNonNull(operatorConsole, "operatorConsole must not be null");
        ClientSelector.Selection selection = selectTarget(uplink, saeNodes, operatorConsole);
        ClientRecord record = new ClientRecord(
                uplink.clientHashHex(),
                selection.clientId(),
                List.of(),
                selection.saeId()
        );
        return new OperatorSelection(record, uplink);
    }

    private static ClientSelector.Selection selectTarget(
            SeSessionUplink uplink,
            List<RmiManager.SaeNode> saeNodes,
            OperatorConsole operatorConsole
    ) throws IOException {
        List<ClientSelector.LabeledOption> clientOptions = buildClientOptions(uplink.peers());
        List<ClientSelector.LabeledOption> saeOptions = buildSaeOptions(saeNodes);
        try {
            return operatorConsole.selectTarget(clientOptions, saeOptions);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Operator target selection failed", e);
        }
    }

    private static List<ClientSelector.LabeledOption> buildClientOptions(
            List<SeSessionUplink.PeerEntry> peers
    ) {
        if (peers.isEmpty()) {
            throw new IllegalArgumentException("uplink must contain at least one peer entry");
        }
        List<ClientSelector.LabeledOption> options = new ArrayList<>(peers.size());
        for (SeSessionUplink.PeerEntry peer : peers) {
            String clientId = peer.hashHex();
            String nickname = peer.nickname();
            String label = nickname.isBlank() ? clientId : nickname.trim();
            options.add(new ClientSelector.LabeledOption(clientId, label));
        }
        return List.copyOf(options);
    }

    private static List<ClientSelector.LabeledOption> buildSaeOptions(List<RmiManager.SaeNode> saeNodes) {
        Objects.requireNonNull(saeNodes, "saeNodes must not be null");
        if (saeNodes.isEmpty()) {
            throw new IllegalArgumentException("saeNodes must contain at least one SAE.");
        }
        List<ClientSelector.LabeledOption> options = new ArrayList<>(saeNodes.size());
        for (RmiManager.SaeNode saeNode : saeNodes) {
            options.add(new ClientSelector.LabeledOption(saeNode.saeId(), saeNode.location()));
        }
        return List.copyOf(options);
    }
}
