package fel.cvut.se;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Provision downlink acknowledgement from the SE over TLS application data.
 *
 * <p>After the full LV downlink is stored on TROPIC01, the device sends {@code SE_OK <bytes>\n}
 * where {@code bytes} is the sum of key payload written (framing not counted). The SAE
 * forwards that count to the operator terminal with {@link #downloadMessage()}.
 */
public final class SeProvisionAck {

    private static final int MAX_LINE = 64;

    private SeProvisionAck() {
    }

    public record Result(long tropicBytes) {

        /** User-facing status after provision completes (1024-byte KB). */
        public String downloadMessage() {
            return String.format("Device consumed %.1f KB", tropicBytes / 1024.0);
        }
    }

    public static Result read(InputStream in) throws IOException {
        String line = readLine(in);
        if (!line.startsWith("SE_OK ")) {
            throw new IOException("Expected SE_OK from device, got: " + line);
        }
        try {
            long bytes = Long.parseLong(line.substring(6).trim());
            if (bytes < 0L) {
                throw new IOException("Invalid SE_OK byte count: " + bytes);
            }
            return new Result(bytes);
        } catch (NumberFormatException e) {
            throw new IOException("Malformed SE_OK line: " + line, e);
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
