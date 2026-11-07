package fel.cvut.unit.node;

import fel.cvut.node.*;
import fel.cvut.se.SeProvisionAck;
import fel.cvut.usb.SeUsbLink;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("unit")
class ProvisionTerminalStatusTest {

    @Test
    void newSharePrintsSuccessOnlyAfterMarkReturns() {
        assertEquals(
                SeProvisionAck.downloadComplete(4096) + "\n" + Node.SHARE_SUCCESSFUL,
                Node.afterDeviceAckStatus(true, true, 4096));
    }

    @Test
    void newShareWithoutMarkIsNotSuccess() {
        assertEquals(
                Node.SHARE_NOT_CONSISTENT,
                Node.afterDeviceAckStatus(true, false, 4096));
    }

    @Test
    void uninitializedDeviceIsNamedOnTheTerminal() {
        assertEquals(
                SeUsbLink.DEVICE_NOT_INITIALIZED,
                Node.provisionFailure(new IOException(SeUsbLink.DEVICE_NOT_INITIALIZED), false));
    }

    @Test
    void storedShareStillPrintsSuccess() {
        assertEquals(
                SeProvisionAck.downloadComplete(4096) + "\n" + Node.SHARE_SUCCESSFUL,
                Node.afterDeviceAckStatus(false, false, 4096));
    }
}
