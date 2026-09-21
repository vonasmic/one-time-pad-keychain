package fel.cvut.usb;

import fel.cvut.se.SeUsbDump;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UsbCdcRxMachineTest {

    @Test
    void tlsArmAbortIsFailedOnly() {
        assertTrue(UsbCdcRxMachine.isTlsArmAbort("failed"));
        assertTrue(UsbCdcRxMachine.isTlsArmAbort("failed\n".strip()));
        assertFalse(UsbCdcRxMachine.isTlsArmAbort("TLS refused: no owner"));
        assertFalse(UsbCdcRxMachine.isTlsArmAbort("TLS aborted"));
        assertFalse(UsbCdcRxMachine.isTlsArmAbort(""));
        assertFalse(UsbCdcRxMachine.isTlsArmAbort(null));
    }

    @Test
    void dumpThenHello() {
        RecordingListener listener = new RecordingListener();
        UsbCdcRxMachine machine = new UsbCdcRxMachine(listener);
        byte[] hello = {0x16, 0x03, 0x03, 0x00, 0x01};
        byte[] pub = new byte[64];
        pub[0] = 0x11;
        byte[] dump = new SeUsbDump(SeUsbDump.OK, pub).encode();

        machine.feed(dump, 0, dump.length);
        SeUsbDump got = machine.takeDump();
        assertEquals(SeUsbDump.OK, got.status);
        assertArrayEquals(pub, got.body);
        assertFalse(machine.isTlsActive());

        machine.feed(hello, 0, hello.length);
        assertArrayEquals(hello, takeAllBytes(machine));
        assertTrue(machine.isTlsActive());
        assertEquals(1, listener.handshakes);
        assertEquals(1, listener.dumps.size());
    }

    @Test
    void dumpBodyMayContainTlsContentType() {
        RecordingListener listener = new RecordingListener();
        UsbCdcRxMachine machine = new UsbCdcRxMachine(listener);
        byte[] body = {0x16, 0x03, 0x03, 0x00};
        byte[] dump = new SeUsbDump(SeUsbDump.OK, body).encode();

        machine.feed(dump, 0, dump.length);
        SeUsbDump got = machine.takeDump();
        assertArrayEquals(body, got.body);
        assertFalse(machine.isTlsActive());
        assertEquals(0, listener.handshakes);
        assertEquals(0, takeAll(machine));
    }

    @Test
    void splitDumpHeaderThenBody() {
        UsbCdcRxMachine machine = new UsbCdcRxMachine(new RecordingListener());
        byte[] body = {1, 2, 3, 4};
        byte[] dump = new SeUsbDump(SeUsbDump.EMPTY, body).encode();

        machine.feed(dump, 0, 2);
        assertNull(machine.takeDump());
        machine.feed(dump, 2, dump.length - 2);
        SeUsbDump got = machine.takeDump();
        assertEquals(SeUsbDump.EMPTY, got.status);
        assertArrayEquals(body, got.body);
    }

    @Test
    void failedAsciiAbortsTlsArm() {
        RecordingListener listener = new RecordingListener();
        UsbCdcRxMachine machine = new UsbCdcRxMachine(listener);
        byte[] frame = ascii("failed\r\n");

        machine.feed(frame, 0, frame.length);
        assertEquals(0, takeAll(machine));
        assertFalse(machine.isTlsActive());
        assertEquals("failed", machine.consumeArmFailure());
        assertNull(machine.consumeArmFailure());
        assertEquals(0, listener.handshakes);
    }

    @Test
    void afterTlsDumpLooksLikeTlsBytes() {
        RecordingListener listener = new RecordingListener();
        UsbCdcRxMachine machine = new UsbCdcRxMachine(listener);
        byte[] hello = {0x16, 0x03, 0x03};
        byte[] dump = new SeUsbDump(SeUsbDump.OK, new byte[] {1}).encode();

        machine.feed(hello, 0, hello.length);
        assertArrayEquals(hello, takeAllBytes(machine));
        assertTrue(machine.isTlsActive());

        machine.feed(dump, 0, dump.length);
        assertArrayEquals(dump, takeAllBytes(machine));
        assertEquals(1, listener.handshakes);
        assertTrue(listener.dumps.isEmpty());
    }

    @Test
    void resetReturnsToDumpMode() {
        RecordingListener listener = new RecordingListener();
        UsbCdcRxMachine machine = new UsbCdcRxMachine(listener);
        byte[] hello = {0x16, 0x03, 0x03, 0x00};

        machine.feed(hello, 0, hello.length);
        assertTrue(takeAll(machine) > 0);
        assertTrue(machine.isTlsActive());

        machine.reset();
        assertFalse(machine.isTlsActive());
        assertEquals(0, machine.pending());
        assertNull(machine.consumeArmFailure());

        byte[] dump = new SeUsbDump(SeUsbDump.REFUSED, null).encode();
        machine.feed(dump, 0, dump.length);
        assertEquals(SeUsbDump.REFUSED, machine.takeDump().status);
        assertFalse(machine.isTlsActive());
        assertEquals(1, listener.dumps.size());
    }

    @Test
    void gluedFailedThenHelloDoesNotArmUntilHello() {
        RecordingListener listener = new RecordingListener();
        UsbCdcRxMachine machine = new UsbCdcRxMachine(listener);
        byte[] hello = {0x16, 0x03};
        byte[] glued = concat(ascii("failed\n"), hello);

        machine.feed(glued, 0, glued.length);
        byte[] got = takeAllBytes(machine);
        assertEquals("failed", machine.consumeArmFailure());
        assertTrue(machine.isTlsActive());
        assertArrayEquals(hello, got);
        assertEquals(1, listener.handshakes);
    }

    private static int takeAll(UsbCdcRxMachine machine) {
        return takeAllBytes(machine).length;
    }

    private static byte[] takeAllBytes(UsbCdcRxMachine machine) {
        byte[] buf = new byte[256];
        int n = machine.takeTls(buf, 0, buf.length);
        if (n <= 0) {
            return new byte[0];
        }
        byte[] out = new byte[n];
        System.arraycopy(buf, 0, out, 0, n);
        return out;
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static final class RecordingListener implements UsbCdcListener {
        final List<SeUsbDump> dumps = new ArrayList<>();
        final List<byte[]> ascii = new ArrayList<>();
        int handshakes;

        @Override
        public void onDump(int status, byte[] body) {
            dumps.add(new SeUsbDump(status, body));
        }

        @Override
        public void onPreTlsAscii(byte[] data, int off, int len) {
            byte[] copy = new byte[len];
            System.arraycopy(data, off, copy, 0, len);
            ascii.add(copy);
        }

        @Override
        public void onTlsHandshakeDetected() {
            handshakes++;
        }
    }
}
