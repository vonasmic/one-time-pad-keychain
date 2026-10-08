package fel.cvut.usb;

import com.fazecast.jSerialComm.SerialPort;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Picks a host CDC node when {@code USB_SERIAL_PORT} is {@code auto} or {@code scan}.
 *
 * <p>The keychain enumerates as ST VID {@code 0483} PID {@code 5710}
 * ({@code USBD_VID} / {@code USBD_PID} in the firmware descriptors). An ST-Link
 * virtual COM is the same VID and a different PID, and it often takes
 * {@code /dev/ttyACM0}, so the app CDC lands on {@code ttyACM1}.
 */
final class CdcPortScan {

    /** STMicroelectronics. */
    static final int STM_VID = 0x0483;
    /** Firmware {@code USBD_PID} ({@code 22288}). */
    static final int KEYCHAIN_PID = 0x5710;

    record Seen(String path, int vendorId, int productId) {}

    private CdcPortScan() {}

    static boolean isAuto(String name) {
        if (name == null) {
            return false;
        }
        String v = name.trim();
        return v.equalsIgnoreCase("auto") || v.equalsIgnoreCase("scan");
    }

    static List<Seen> list() {
        List<Seen> out = new ArrayList<>();
        for (SerialPort port : SerialPort.getCommPorts()) {
            String path = port.getSystemPortPath();
            if (path == null || path.isBlank()) {
                continue;
            }
            int vid = port.getVendorID();
            int pid = port.getProductID();
            boolean acm = fileName(path).startsWith("ttyACM");
            boolean keychain = vid == STM_VID && pid == KEYCHAIN_PID;
            if (acm || keychain) {
                out.add(new Seen(path, vid, pid));
            }
        }
        out.sort(Comparator.comparing(Seen::path));
        return out;
    }

    /**
     * One path to open, or {@code null} when none or several candidates are present.
     * A unique {@code 0483:5710} wins over other {@code ttyACM} nodes.
     */
    static String choose(List<Seen> ports) {
        List<String> ids = matching(ports);
        if (ids.size() == 1) {
            return ids.get(0);
        }
        if (ids.size() > 1) {
            return null;
        }
        List<String> acm = acmPaths(ports);
        if (acm.size() == 1) {
            return acm.get(0);
        }
        return null;
    }

    static String waitMessage(List<Seen> ports) {
        List<String> ids = matching(ports);
        if (ids.size() > 1) {
            return "[usb] Several keychain CDC devices, waiting for one: " + ids;
        }
        List<String> acm = acmPaths(ports);
        if (ids.isEmpty() && acm.size() > 1) {
            return "[usb] Several /dev/ttyACM* devices and none match 0483:5710. "
                    + "Set USB_SERIAL_PORT to one of them, or unplug the extra device. Seen: "
                    + ports.stream().map(Seen::path).toList();
        }
        return "[usb] Waiting for a USB CDC device (0483:5710, or a single /dev/ttyACM*) ...";
    }

    private static List<String> matching(List<Seen> ports) {
        List<String> ids = new ArrayList<>();
        for (Seen port : ports) {
            if (port.vendorId() == STM_VID && port.productId() == KEYCHAIN_PID) {
                ids.add(port.path());
            }
        }
        return ids;
    }

    private static List<String> acmPaths(List<Seen> ports) {
        List<String> acm = new ArrayList<>();
        for (Seen port : ports) {
            if (fileName(port.path()).startsWith("ttyACM") && !acm.contains(port.path())) {
                acm.add(port.path());
            }
        }
        return acm;
    }

    private static String fileName(String path) {
        Path file = Path.of(path).getFileName();
        return file == null ? path : file.toString();
    }
}
