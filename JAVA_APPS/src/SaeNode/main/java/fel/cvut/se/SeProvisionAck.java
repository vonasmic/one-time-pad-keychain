package fel.cvut.se;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Provision downlink acknowledgement from the SE over TLS application data.
 *
 * <p>After the full LV downlink is stored on TROPIC01, the device sends {@code SE_OK\n}.
 * The SAE reports the downlink size it wrote ({@link #downloadMessage(long)}), not a
 * device-side byte count.
 */
public final class SeProvisionAck {

    private static final int MAX_LINE = 64;

    private SeProvisionAck() {
    }

    /** User-facing status after provision completes (1024-byte KB). */
    public static String downloadMessage(long nodeBytes) {
        return String.format("Sent %.1f KB", nodeBytes / 1024.0);
    }

    public static void read(InputStream in) throws IOException {
        String line = readLine(in);
        if (!line.equals("SE_OK")) {
            throw new IOException("Expected SE_OK from device, got: " + line);
        }
    }

    private static String readLine(InputStream in) throws IOException {
        byte[] buf = new byte[MAX_LINE];
        int len = 0;
        while (len < MAX_LINE) {
            int b = in.read();
            if (b < 0) {
                throw new IOException("TLS closed before SE_OK"
                        + (len > 0 ? " (partial: " + new String(buf, 0, len, StandardCharsets.US_ASCII) + ")"
                        : ""));
            }
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                buf[len++] = (byte) b;
            }
        }
        if (len >= MAX_LINE) {
            throw new IOException("SE_OK line too long");
        }
        return new String(buf, 0, len, StandardCharsets.US_ASCII).strip();
    }
}
