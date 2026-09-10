package fel.cvut.usb;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SeUsbLinkTest {

    @Test
    void tlsArmAbortDetectsFirmwareRefusals() {
        assertTrue(SeUsbLink.isTlsArmAbort("TLS refused: no owner"));
        assertTrue(SeUsbLink.isTlsArmAbort("TLS refused: not provision-ready"));
        assertTrue(SeUsbLink.isTlsArmAbort("TLS refused: not encrypt-ready"));
        assertTrue(SeUsbLink.isTlsArmAbort("TLS start failed"));
        assertTrue(SeUsbLink.isTlsArmAbort("TLS setup: no SAE CA"));
        assertTrue(SeUsbLink.isTlsArmAbort("TLS aborted"));
    }

    @Test
    void tlsArmAbortIgnoresProgressDebug() {
        assertFalse(SeUsbLink.isTlsArmAbort("time synced unix=1789048415"));
        assertFalse(SeUsbLink.isTlsArmAbort("sending handshake"));
        assertFalse(SeUsbLink.isTlsArmAbort("TLS session ok"));
        assertFalse(SeUsbLink.isTlsArmAbort("handshake ok, manage"));
        assertFalse(SeUsbLink.isTlsArmAbort(""));
        assertFalse(SeUsbLink.isTlsArmAbort(null));
    }
}
