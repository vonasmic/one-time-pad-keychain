package fel.cvut.node;

import fel.cvut.node.interNodeCommunication.RmiManager;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeSessionUplink;
import fel.cvut.terminal.ClientSelector;
import fel.cvut.terminal.OperatorConsole;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class InputHandlerTest {

    @Test
    void selectForUplinkStoresMinWhenChipIsSmaller() throws Exception {
        SeSessionUplink.PeerEntry peer = peer(64);
        InputHandler.OperatorSelection selection = select(uplink(64, peer), peer);

        assertEquals(64 - SeConstants.RMEM_OVERHEAD, selection.clientRecord().getClientHeader().padPlainLen());
    }

    @Test
    void selectForUplinkStoresMinWhenPeerIsSmaller() throws Exception {
        SeSessionUplink.PeerEntry peer = peer(35);
        InputHandler.OperatorSelection selection = select(uplink(475, peer), peer);

        assertEquals(35, selection.clientRecord().getClientHeader().padPlainLen());
    }

    private static InputHandler.OperatorSelection select(
            SeSessionUplink uplink, SeSessionUplink.PeerEntry peer
    ) throws Exception {
        OperatorConsole operator = mock(OperatorConsole.class);
        when(operator.selectTarget(anyList(), anyList()))
                .thenReturn(new ClientSelector.Selection(peer.hashHex(), "sae-2"));
        return new InputHandler().selectForUplink(
                uplink, List.of(new RmiManager.SaeNode("sae-2", "lab")), operator);
    }

    private static SeSessionUplink.PeerEntry peer(int padPlain) {
        byte[] hash = new byte[SeConstants.PEER_HASH_LEN];
        hash[0] = 0x11;
        return new SeSessionUplink.PeerEntry(hash, "alice", padPlain);
    }

    private static SeSessionUplink uplink(int slotSize, SeSessionUplink.PeerEntry peer) {
        return new SeSessionUplink(
                new byte[SeConstants.CLIENT_HASH_LEN],
                slotSize,
                1,
                new byte[SeConstants.FILL_ID_LEN],
                new byte[SeConstants.MLKEM_PK_LEN],
                List.of(peer));
    }
}
