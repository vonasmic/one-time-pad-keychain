package fel.cvut.node;

import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.terminal.ClientSelector;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Handles incoming socket payload parsing and user-driven selection.
 */
public class InputHandler {

    public ClientRecord handleInput(InputStream in, List<RmiManager.SaeNode> saeNodes) throws IOException {
        Objects.requireNonNull(in, "in must not be null");
        ServerKeyPayload payload = ServerKeyPayload.readFrom(in);

        byte[] clientPublicKey = payload.getClientPublicKey();
        validateBytes(clientPublicKey, "clientPublicKey");
        List<ClientSelector.LabeledOption> clientOptions = buildClientOptions(payload.getArray());
        List<ClientSelector.LabeledOption> saeOptions = buildSaeOptions(saeNodes);

        ClientSelector.Selection selection = ClientSelector.select(clientOptions, saeOptions);
        String clientHash1 = toHex(sha256(clientPublicKey));
        String clientHash2 = selection.clientId();
        return new ClientRecord(clientHash1, clientHash2, List.of(), selection.saeId());
    }

    private static List<ClientSelector.LabeledOption> buildClientOptions(
            List<ServerKeyPayload.SecondPartyKeyEntry> entries
    ) {
        if (entries == null || entries.isEmpty()) {
            throw new IllegalArgumentException("array must contain at least one secondPartyKey.");
        }
        List<ClientSelector.LabeledOption> options = new ArrayList<>();
        for (ServerKeyPayload.SecondPartyKeyEntry entry : entries) {
            if (entry == null || entry.getSecondPartyKey() == null || entry.getSecondPartyKey().length == 0) {
                continue;
            }
            String clientId = toHex(sha256(entry.getSecondPartyKey()));
            String nickname = entry.getNickname();
            String label = (nickname == null || nickname.isBlank()) ? clientId : nickname.trim();
            options.add(new ClientSelector.LabeledOption(clientId, label));
        }
        if (options.isEmpty()) {
            throw new IllegalArgumentException("No valid secondPartyKey values were provided.");
        }
        return List.copyOf(options);
    }

    private static List<ClientSelector.LabeledOption> buildSaeOptions(List<RmiManager.SaeNode> saeNodes) {
        Objects.requireNonNull(saeNodes, "saeNodes must not be null");
        List<ClientSelector.LabeledOption> options = new ArrayList<>();
        for (RmiManager.SaeNode saeNode : saeNodes) {
            if (saeNode == null) {
                continue;
            }
            options.add(new ClientSelector.LabeledOption(saeNode.saeId(), saeNode.location()));
        }
        if (options.isEmpty()) {
            throw new IllegalArgumentException("saeNodes must contain at least one SAE.");
        }
        return List.copyOf(options);
    }

    private static byte[] sha256(byte[] value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(value);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available.", ex);
        }
    }

    private static String toHex(byte[] value) {
        StringBuilder builder = new StringBuilder(value.length * 2);
        for (byte b : value) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    private static void validateBytes(byte[] value, String fieldName) {
        if (value == null || value.length == 0) {
            throw new IllegalArgumentException(fieldName + " must not be null or empty.");
        }
    }
}
