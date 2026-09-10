package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChipInitTest {

    @Test
    void occupiedAndFailuresAreDetected() {
        assertTrue(ChipInit.slotOccupied("TROPIC slot occupied"));
        assertFalse(ChipInit.slotOccupied("TROPIC ping ok"));
        assertTrue(ChipInit.chipFailed("TROPIC command failed"));
        assertTrue(ChipInit.chipFailed("KEM INIT PIN mismatch"));
        assertTrue(ChipInit.chipFailed("DEVICE_TAMPERED"));
        assertTrue(ChipInit.chipFailed(null));
        assertTrue(ChipInit.chipFailed(""));
        assertFalse(ChipInit.chipFailed(
                "WARNING: factory SH0 (pairing slot 0) will be INVALIDATED\nTROPIC PAIRING 1 y"));
        assertTrue(ChipInit.pairingSlotRejected("TROPIC PAIRING slot must be 1-3"));
        assertFalse(ChipInit.pairingSlotRejected("WARNING: PAIRING writes a new X25519 access key"));
        assertFalse(ChipInit.chipFailed(
                "TROPIC PAIRING KEY 1 " + "aa".repeat(32) + " " + "bb".repeat(32)));
        assertFalse(ChipInit.chipFailed("TROPIC PAIRING LOAD ok"));
        assertTrue(ChipInit.okLine("TROPIC PAIRING LOAD ok", "pairing load ok"));
    }

    @Test
    void pairingChoiceAcceptsSlotsOrSkip() {
        assertEquals("1", ChipInit.parsePairingChoice("1"));
        assertEquals("3", ChipInit.parsePairingChoice(" 3 "));
        assertEquals("n", ChipInit.parsePairingChoice("n"));
        assertEquals("n", ChipInit.parsePairingChoice("N"));
        assertTrue(ChipInit.isSkipPairing("n"));
        assertFalse(ChipInit.isSkipPairing("1"));
        assertNull(ChipInit.parsePairingChoice("0"));
        assertNull(ChipInit.parsePairingChoice("yes"));
        assertNull(ChipInit.parsePairingChoice(""));
        assertNull(ChipInit.parsePairingChoice(null));
    }

    @Test
    void parsesPairingKeyLineFromConsole() {
        String priv = "11".repeat(32);
        String pub = "22".repeat(32);
        String reply = """
                TROPIC pairing pub slot 1:
                %s
                TROPIC PAIRING KEY 1 %s %s
                TROPIC factory SH0 invalidated
                """.formatted("22".repeat(32), priv, pub);
        ChipInit.PairingBackup key = ChipInit.PairingBackup.parseReply(reply);
        assertNotNull(key);
        assertEquals(1, key.slot());
        assertEquals(priv, SeBytes.toHex(key.priv()));
        assertEquals(pub, SeBytes.toHex(key.pub()));
        assertEquals("TROPIC PAIRING LOAD 1 " + priv + " " + pub, key.loadCommand());
        assertNull(ChipInit.PairingBackup.parseReply("TROPIC factory SH0 invalidated"));
    }

    @Test
    void pairingFileRoundTrip(@TempDir Path dir) throws Exception {
        ChipInit.PairingBackup original = new ChipInit.PairingBackup(
                2, SeBytes.fromHex("ab".repeat(32)), SeBytes.fromHex("cd".repeat(32)));
        Path file = dir.resolve("client").resolve("pairing.key");
        original.save(file);
        assertTrue(Files.isRegularFile(file));
        ChipInit.PairingBackup loaded = ChipInit.PairingBackup.readFile(file);
        assertEquals(2, loaded.slot());
        assertEquals(SeBytes.toHex(original.priv()), SeBytes.toHex(loaded.priv()));
        assertEquals(SeBytes.toHex(original.pub()), SeBytes.toHex(loaded.pub()));
        assertTrue(loaded.loadCommand().length() <= 160);
    }
}
