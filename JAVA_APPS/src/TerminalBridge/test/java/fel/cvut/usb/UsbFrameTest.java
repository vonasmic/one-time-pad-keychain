package fel.cvut.usb;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class UsbFrameTest {

    @Test
    void roundTripCommand() {
        byte[] payload = "CLIENT CSR".getBytes(StandardCharsets.US_ASCII);
        byte[] wire = UsbFrame.encode(UsbFrame.TYPE_CMD, payload);
        UsbFrame.Decoder decoder = new UsbFrame.Decoder();
        decoder.add(wire, 0, wire.length);
        UsbFrame.Parsed got = decoder.take();
        assertEquals(UsbFrame.TYPE_CMD, got.type());
        assertArrayEquals(payload, got.payload());
        assertNull(decoder.take());
    }

    @Test
    void splitHeaderThenPayload() {
        byte[] payload = new byte[] { 0x16, 0x03, 0x03 };
        byte[] wire = UsbFrame.encode(UsbFrame.TYPE_SECURE, payload);
        UsbFrame.Decoder decoder = new UsbFrame.Decoder();
        decoder.add(wire, 0, 3);
        assertNull(decoder.take());
        decoder.add(wire, 3, wire.length - 3);
        UsbFrame.Parsed got = decoder.take();
        assertEquals(UsbFrame.TYPE_SECURE, got.type());
        assertArrayEquals(payload, got.payload());
    }

    @Test
    void commandLeftAsideFromSecure() {
        byte[] cmd = UsbFrame.encode(UsbFrame.TYPE_CMD, "HELP".getBytes(StandardCharsets.US_ASCII));
        byte[] sec = UsbFrame.encode(UsbFrame.TYPE_SECURE, new byte[] { 0x16 });
        UsbFrame.Decoder decoder = new UsbFrame.Decoder();
        decoder.add(cmd, 0, cmd.length);
        decoder.add(sec, 0, sec.length);
        UsbFrame.Parsed first = decoder.take();
        UsbFrame.Parsed second = decoder.take();
        assertEquals(UsbFrame.TYPE_CMD, first.type());
        assertEquals("HELP", new String(first.payload(), StandardCharsets.US_ASCII));
        assertEquals(UsbFrame.TYPE_SECURE, second.type());
        assertArrayEquals(new byte[] { 0x16 }, second.payload());
    }

    @Test
    void junkBeforeMagicIsSkipped() {
        byte[] payload = "ok".getBytes(StandardCharsets.US_ASCII);
        byte[] frame = UsbFrame.encode(UsbFrame.TYPE_CMD, payload);
        byte[] wire = new byte[frame.length + 3];
        wire[0] = 0x16;
        wire[1] = (byte) 0xAA;
        wire[2] = 0x00;
        System.arraycopy(frame, 0, wire, 3, frame.length);
        UsbFrame.Decoder decoder = new UsbFrame.Decoder();
        decoder.add(wire, 0, wire.length);
        UsbFrame.Parsed got = decoder.take();
        assertEquals("ok", new String(got.payload(), StandardCharsets.US_ASCII));
    }

    @Test
    void encodeSplitChunksAtMaxPayload() {
        byte[] body = new byte[UsbFrame.MAX_PAYLOAD + 4];
        body[0] = 1;
        body[UsbFrame.MAX_PAYLOAD] = 2;
        List<byte[]> frames = UsbFrame.encodeSplit(UsbFrame.TYPE_SECURE, body, 0, body.length);
        assertEquals(2, frames.size());
        UsbFrame.Decoder decoder = new UsbFrame.Decoder();
        for (byte[] frame : frames) {
            decoder.add(frame, 0, frame.length);
        }
        assertEquals(UsbFrame.MAX_PAYLOAD, decoder.take().payload().length);
        assertEquals(4, decoder.take().payload().length);
    }
}
