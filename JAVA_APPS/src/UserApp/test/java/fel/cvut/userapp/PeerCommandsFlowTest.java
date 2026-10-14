package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeManage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Scanner;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@Tag("unit")
class PeerCommandsFlowTest {

    private static final String HASH = "ab".repeat(48);
    private static final SeManage.Reply OK = new SeManage.Reply(SeManage.OK, "ok");
    private static final SeManage.Reply FAIL = new SeManage.Reply(SeManage.BAD_CMD, "no slot");

    private ChipService chip;

    @BeforeEach
    void setUp() {
        chip = mock(ChipService.class);
    }

    @Test
    void listPrintsPeersOrPlaceholder() throws Exception {
        when(chip.peerList()).thenReturn("", "alice 32\n");
        PeerCommands.run(new Scanner(""), chip, "PEER LIST");
        PeerCommands.run(new Scanner(""), chip, "peer l");
        verify(chip, org.mockito.Mockito.times(2)).peerList();
    }

    @Test
    void bareCommandPromptsForSubcommand() throws Exception {
        when(chip.peerList()).thenReturn(null);
        PeerCommands.run(new Scanner("list\n"), chip, "PEER");
        verify(chip).peerList();
    }



    @Test
    void addWithInlineNicknameSendsParsedHashAndPad() throws Exception {
        when(chip.peerAdd(anyString(), any(), anyInt())).thenReturn(OK);
        PeerCommands.run(new Scanner(HASH.toUpperCase() + "\n 48 \n"), chip, "PEER ADD Bob_1");
        verify(chip).peerAdd(eq("Bob_1"), eq(SeBytes.fromHex(HASH)), eq(48));
    }

    @Test
    void addPromptsForNicknameWhenMissing() throws Exception {
        when(chip.peerAdd(anyString(), any(), anyInt())).thenReturn(FAIL);
        PeerCommands.run(new Scanner("carol\n" + HASH + "\n7\n"), chip, "PEER ADD");
        verify(chip).peerAdd(eq("carol"), eq(SeBytes.fromHex(HASH)), eq(7));
    }

    @Test
    void addStopsOnInvalidInputs() throws Exception {
        PeerCommands.run(new Scanner(""), chip, "PEER ADD bad nick!");
        PeerCommands.run(new Scanner("abcd\n"), chip, "PEER ADD bob");
        PeerCommands.run(new Scanner(HASH + "\n0\n"), chip, "PEER ADD bob");
        PeerCommands.run(new Scanner(HASH + "\nlots\n"), chip, "PEER ADD bob");
        PeerCommands.run(new Scanner(HASH + "\n"), chip, "PEER ADD bob");
        PeerCommands.run(new Scanner("\n"), chip, "PEER ADD bob");
        PeerCommands.run(new Scanner(""), chip, "PEER A");
        verifyNoInteractions(chip);
    }

    @Test
    void removeReportsSuccessAndFailure() throws Exception {
        when(chip.peerRemove("bob")).thenReturn(OK);
        when(chip.peerRemove("eve")).thenReturn(FAIL);
        PeerCommands.run(new Scanner(""), chip, "PEER REMOVE bob");
        PeerCommands.run(new Scanner("eve\n"), chip, "PEER R");
        verify(chip).peerRemove("bob");
        verify(chip).peerRemove("eve");
    }

    @Test
    void removeRejectsInvalidNickname() throws Exception {
        PeerCommands.run(new Scanner(""), chip, "PEER REMOVE " + "x".repeat(17));
        verify(chip, never()).peerRemove(anyString());
    }

    @Test
    void cardReadsLocalIdentity() throws Exception {
        when(chip.clientHashHex()).thenReturn(HASH.substring(0, 48) + "\n" + HASH.substring(48));
        when(chip.tropicPadLen()).thenReturn("32\n");
        PeerCommands.run(new Scanner(""), chip, "PEER CARD alice");
        verify(chip).clientHashHex();
        verify(chip).tropicPadLen();
    }

    @Test
    void cardStopsWhenChipHashIsInvalid() throws Exception {
        when(chip.clientHashHex()).thenReturn("failed");
        PeerCommands.run(new Scanner(""), chip, "PEER CARD alice");
        verify(chip, never()).tropicPadLen();
    }

    @Test
    void clientInfoValidatesNicknameAndReadsIdentity() throws Exception {
        when(chip.clientHashHex()).thenReturn(HASH);
        when(chip.tropicPadLen()).thenReturn("empty");
        PeerCommands.clientInfo(new Scanner(""), chip, "CLIENT INFO alice");
        verify(chip).tropicPadLen();

        ChipService untouched = mock(ChipService.class);
        PeerCommands.clientInfo(new Scanner(""), untouched, "CLIENT INFO not valid!");
        PeerCommands.clientInfo(new Scanner(""), untouched, "CLIENT INFO");
        verifyNoInteractions(untouched);
    }

    @Test
    void clientInfoPromptsForName() throws Exception {
        when(chip.clientHashHex()).thenReturn(HASH);
        when(chip.tropicPadLen()).thenReturn("16");
        PeerCommands.clientInfo(new Scanner("dave\n"), chip, "client info");
        verify(chip).clientHashHex();
    }
}