package fel.cvut.usb;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CdcPortScanTest {

    @Test
    void autoTokens() {
        assertTrue(CdcPortScan.isAuto("auto"));
        assertTrue(CdcPortScan.isAuto("SCAN"));
        assertFalse(CdcPortScan.isAuto("/dev/ttyACM1"));
        assertFalse(CdcPortScan.isAuto(null));
    }

    @Test
    void prefersKeychainIdOverStLink() {
        var ports = List.of(
                new CdcPortScan.Seen("/dev/ttyACM0", CdcPortScan.STM_VID, 0x374B),
                new CdcPortScan.Seen("/dev/ttyACM1", CdcPortScan.STM_VID, CdcPortScan.KEYCHAIN_PID));
        assertEquals("/dev/ttyACM1", CdcPortScan.choose(ports));
    }

    @Test
    void singleAcmWhenIdsAreMissing() {
        var ports = List.of(new CdcPortScan.Seen("/dev/ttyACM2", -1, -1));
        assertEquals("/dev/ttyACM2", CdcPortScan.choose(ports));
    }

    @Test
    void waitsWhenSeveralAcmHaveNoKeychainId() {
        var ports = List.of(
                new CdcPortScan.Seen("/dev/ttyACM0", -1, -1),
                new CdcPortScan.Seen("/dev/ttyACM1", -1, -1));
        assertNull(CdcPortScan.choose(ports));
        assertTrue(CdcPortScan.waitMessage(ports).contains("ttyACM0"));
    }

    @Test
    void emptyListWaits() {
        assertNull(CdcPortScan.choose(List.of()));
    }
}
