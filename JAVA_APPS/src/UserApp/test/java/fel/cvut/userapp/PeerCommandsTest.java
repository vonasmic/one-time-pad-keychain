package fel.cvut.userapp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PeerCommandsTest {

    @Test
    void parsePadPlainAcceptsDecimal() {
        assertEquals(446, PeerCommands.parsePadPlain("446"));
        assertEquals(35, PeerCommands.parsePadPlain("35\n"));
    }

    @Test
    void parsePadPlainRejectsZeroAndNonDecimal() {
        assertThrows(IllegalArgumentException.class, () -> PeerCommands.parsePadPlain("0"));
        assertThrows(IllegalArgumentException.class, () -> PeerCommands.parsePadPlain("failed"));
        assertThrows(IllegalArgumentException.class, () -> PeerCommands.parsePadPlain("abc"));
    }
}
