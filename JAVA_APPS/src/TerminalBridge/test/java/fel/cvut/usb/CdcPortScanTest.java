package fel.cvut.usb;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CdcPortScanTest {

    @Test
    void autoTokens() {
        assertTrue(CdcPortScan.isAuto("auto"));
        assertTrue(CdcPortScan.isAuto("SCAN"));
        assertTrue(!CdcPortScan.isAuto("/dev/ttyACM1"));
        assertTrue(!CdcPortScan.isAuto(null));
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
    void waitsWhenTwoKeychainsArePlugged() {
        var ports = List.of(
                new CdcPortScan.Seen("/dev/ttyACM0", CdcPortScan.STM_VID, CdcPortScan.KEYCHAIN_PID),
                new CdcPortScan.Seen("/dev/ttyACM3", CdcPortScan.STM_VID, CdcPortScan.KEYCHAIN_PID));
        assertNull(CdcPortScan.choose(ports));
    }

    @Test
    void emptyListWaits() {
        assertNull(CdcPortScan.choose(List.of()));
    }
}
