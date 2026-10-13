package fel.cvut.se;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.IntConsumer;

/**
 * Provision downlink handshake from the SE over TLS application data.
 *
 * <p>After the uplink, the device erases QKD R-MEM and sends
 * {@code TROPIC_WIPE_FINISHED}. SAE then streams the LV downlink. About every
 * 10 KiB the device sends the integer KiB consumed so far. After the full
 * downlink is stored, the device sends {@code SE_OK\n}.
 */
public final class SeProvisionAck {

    public static final String WIPE_FINISHED = "TROPIC_WIPE_FINISHED";
    public static final int PROGRESS_BYTES = 10 * 1024;

    private static final int MAX_LINE = 64;
    private static final int BAR_WIDTH = 10;
    private static final String LOAD_LABEL = "Loading to device";

    private SeProvisionAck() {
    }

    /**
     * Progress line from a device KB report. Percent stays under 100 until
     * {@link #downloadComplete(long)} after {@code SE_OK}.
     */
    public static String downloadProgress(int reportedKb, long totalBytes) {
        long totalKb = Math.max(1L, totalBytes / 1024L);
        long pct = 0L;
        if (totalBytes > 0L) {
            pct = Math.min(99L, (reportedKb * 1024L * 100L) / totalBytes);
        }
        return formatProgress(pct, reportedKb, totalKb);
    }

    /** Full bar after {@code SE_OK}. Kilobytes match {@link #downloadProgress(int, long)}. */
    public static String downloadComplete(long totalBytes) {
        long totalKb = Math.max(1L, totalBytes / 1024L);
        return formatProgress(100L, totalKb, totalKb);
    }

    private static String formatProgress(long pct, long doneKb, long totalKb) {
        int filled = (int) ((pct * BAR_WIDTH) / 100L);
        StringBuilder bar = new StringBuilder(BAR_WIDTH);
        for (int i = 0; i < BAR_WIDTH; i++) {
            bar.append(i < filled ? '#' : '-');
        }
        return String.format(
                "%s: [%s] %d%% (%d of %d KB)",
                LOAD_LABEL, bar, pct, doneKb, totalKb);
    }

    public static void awaitWipeFinished(InputStream in) throws IOException {
        String line = readLine(in);
        if (!line.equals(WIPE_FINISHED)) {
            throw new IOException("Expected " + WIPE_FINISHED + " from device, got: " + line);
        }
    }

    /**
     * Writes {@code payload} in {@link #PROGRESS_BYTES} chunks. After a chunk
     * that lands on a 10 KiB boundary, reads one integer KB line from {@code in}.
     * A short tail does not wait for another KB line.
     */
    public static void writeTracking(
            OutputStream out, InputStream in, byte[] payload, IntConsumer onKb
    ) throws IOException {
        int off = 0;
        while (off < payload.length) {
            int n = Math.min(PROGRESS_BYTES, payload.length - off);
            out.write(payload, off, n);
            out.flush();
            off += n;
            if ((off % PROGRESS_BYTES) == 0) {
                int kb = readKbLine(in);
                if (onKb != null) {
                    onKb.accept(kb);
                }
            }
        }
    }

    public static void read(InputStream in) throws IOException {
        String line = readLine(in);
        if (!line.equals("SE_OK")) {
            throw new IOException("Expected SE_OK from device, got: " + line);
        }
    }

    private static int readKbLine(InputStream in) throws IOException {
        String line = readLine(in);
        try {
            return Integer.parseInt(line);
        } catch (NumberFormatException ex) {
            throw new IOException("Expected KB progress from device, got: " + line);
        }
    }

    private static String readLine(InputStream in) throws IOException {
        byte[] buf = new byte[MAX_LINE];
        int len = 0;
        while (len < MAX_LINE) {
            int b = in.read();
            if (b < 0) {
                throw new IOException("TLS closed before provision line"
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
            throw new IOException("provision line too long");
        }
        return new String(buf, 0, len, StandardCharsets.US_ASCII).strip();
    }
}
