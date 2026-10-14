package fel.cvut.unit.se;

import fel.cvut.se.SeBytes;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class SeBytesTest {



    @Test
    void hexRoundTripAndWhitespaceTolerance() {
        byte[] value = {0x00, 0x7f, (byte) 0x80, (byte) 0xff};
        assertEquals("007f80ff", SeBytes.toHex(value));
        assertArrayEquals(value, SeBytes.fromHex("007f80ff"));
        assertArrayEquals(value, SeBytes.fromHex(" 00 7F\n80\tFF "));
        assertArrayEquals(new byte[0], SeBytes.fromHex(""));
    }

    @Test
    void fromHexRejectsNullOddAndInvalid() {
        assertThrows(IllegalArgumentException.class, () -> SeBytes.fromHex(null));
        IllegalArgumentException odd = assertThrows(IllegalArgumentException.class, () -> SeBytes.fromHex("abc"));
        assertTrue(odd.getMessage().contains("even"));
        IllegalArgumentException bad = assertThrows(IllegalArgumentException.class, () -> SeBytes.fromHex("00zz"));
        assertTrue(bad.getMessage().contains("index 2"), bad.getMessage());
    }

    @Test
    void littleEndianEncodersMatchStreamDecoders() throws IOException {
        assertArrayEquals(new byte[] {0x34, 0x12}, SeBytes.u16Le(0x1234));
        assertArrayEquals(new byte[] {0x78, 0x56, 0x34, 0x12}, SeBytes.u32Le(0x12345678));
        assertEquals(0xBEEF, SeBytes.readU16Le(new ByteArrayInputStream(SeBytes.u16Le(0xBEEF))));
        assertEquals(0xCAFEBABE, SeBytes.readU32Le(new ByteArrayInputStream(SeBytes.u32Le(0xCAFEBABE))));
        assertEquals(0xFFFF, SeBytes.readU16Le(new byte[] {(byte) 0xff, (byte) 0xff}, "len"));
    }

    @Test
    void readU16LeArrayRejectsWrongLength() {
        IOException ex = assertThrows(IOException.class, () -> SeBytes.readU16Le(new byte[3], "slot"));
        assertTrue(ex.getMessage().startsWith("slot"));
        assertThrows(IOException.class, () -> SeBytes.readU16Le((byte[]) null, "slot"));
    }

    @Test
    void streamReadersFailOnTruncation() {
        assertThrows(EOFException.class, () -> SeBytes.readU16Le(new ByteArrayInputStream(new byte[] {1})));
        assertThrows(EOFException.class, () -> SeBytes.readU32Le(new ByteArrayInputStream(new byte[] {1, 2, 3})));
        assertThrows(EOFException.class, () -> SeBytes.readFullyOne(new ByteArrayInputStream(new byte[0])));
        EOFException ex = assertThrows(EOFException.class,
                () -> SeBytes.readFully(new ByteArrayInputStream(new byte[] {1, 2}), new byte[4]));
        assertTrue(ex.getMessage().contains("offset 2"), ex.getMessage());
    }

    @Test
    void readFullyToleratesShortAndZeroLengthReads() throws IOException {
        byte[] source = {1, 2, 3, 4, 5};
        InputStream trickle = new InputStream() {
            private int pos;
            private boolean zeroNext = true;

            @Override
            public int read() {
                return pos < source.length ? source[pos++] : -1;
            }

            @Override
            public int read(byte[] b, int off, int len) {
                if (zeroNext) {
                    zeroNext = false;
                    return 0;
                }
                zeroNext = true;
                if (pos >= source.length) {
                    return -1;
                }
                b[off] = source[pos++];
                return 1;
            }
        };
        byte[] dest = new byte[5];
        SeBytes.readFully(trickle, dest);
        assertArrayEquals(source, dest);
    }

    @Test
    void requireLenAcceptsExactAndRejectsOthers() throws IOException {
        byte[] ok = new byte[4];
        assertSame(ok, SeBytes.requireLen(ok, 4, "x"));
        IOException wrong = assertThrows(IOException.class, () -> SeBytes.requireLen(new byte[3], 4, "fill_id"));
        assertEquals("fill_id must be 4 bytes, got 3", wrong.getMessage());
        IOException nul = assertThrows(IOException.class, () -> SeBytes.requireLen(null, 4, "fill_id"));
        assertTrue(nul.getMessage().endsWith("got null"));
    }

    @Test
    void decodeAndConcatBase64JoinsDecodedKeys() {
        String a = Base64.getEncoder().encodeToString(new byte[] {1, 2});
        String b = Base64.getEncoder().encodeToString(new byte[] {3});
        assertArrayEquals(new byte[] {1, 2, 3}, SeBytes.decodeAndConcatBase64(List.of(a, b)));
        assertEquals(3, SeBytes.decodedBase64ByteLength(List.of(a, b)));
    }

    @Test
    void decodeAndConcatBase64RejectsBadInput() {
        assertThrows(IllegalArgumentException.class, () -> SeBytes.decodeAndConcatBase64(null));
        assertThrows(IllegalArgumentException.class, () -> SeBytes.decodeAndConcatBase64(List.of()));
        List<String> withNull = new ArrayList<>();
        withNull.add(null);
        assertThrows(IllegalArgumentException.class, () -> SeBytes.decodeAndConcatBase64(withNull));
        assertThrows(IllegalArgumentException.class, () -> SeBytes.decodeAndConcatBase64(List.of("  ")));
        IllegalArgumentException notB64 = assertThrows(IllegalArgumentException.class,
                () -> SeBytes.decodeAndConcatBase64(List.of("!!!!")));
        assertTrue(notB64.getMessage().contains("not valid base64"));
        IllegalArgumentException empty = assertThrows(IllegalArgumentException.class,
                () -> SeBytes.decodeAndConcatBase64(List.of("====")));
        assertTrue(empty.getMessage().contains("empty") || empty.getMessage().contains("base64"));
    }

}