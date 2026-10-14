package fel.cvut.userapp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class ConsoleStyleTest {

    @Test
    void colorIsMeaningAndCanBeTurnedOff() {
        assertEquals("OK", ConsoleStyle.decorate("OK", "\u001B[32m", true, false, false, false));
        String painted = ConsoleStyle.decorate("OK", "\u001B[32m", true, false, true, true);
        assertTrue(painted.startsWith("\u001B[1m\u001B[32mOK"));
        assertTrue(painted.endsWith("\u001B[0m"));
    }

    @Test
    void noColorKeepsBoldAndDropsHue() {
        String painted = ConsoleStyle.decorate("INIT", "\u001B[34m", true, false, false, true);
        assertEquals("\u001B[1mINIT\u001B[0m", painted);
        assertFalse(painted.contains("\u001B[34m"));
    }

    @Test
    void repliesSplitFailureFromHex() {
        assertTrue(ConsoleStyle.isFailure("failed"));
        assertTrue(ConsoleStyle.isFailure("failed: no owner"));
        assertFalse(ConsoleStyle.isFailure("Owner enrolled"));
        assertTrue(ConsoleStyle.isHexBlock("01000000fd000800"));
        assertFalse(ConsoleStyle.isHexBlock("OK encrypt reply (hex):\n01000000fd000800"));
    }
}
