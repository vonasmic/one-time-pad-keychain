package fel.cvut.usb;

import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * Blocking {@link InputStream} over a source that waits only briefly for data, with a read
 * timeout in the sense of {@link java.net.Socket#setSoTimeout}: a read that receives no byte
 * within the timeout throws {@link SocketTimeoutException}, and the stream stays usable. A
 * timeout of 0 waits until data arrives or the source ends. {@link StreamSocket#setSoTimeout}
 * sets the timeout, so the timeout an {@code SSLSocket} layered over the USB link is given
 * applies to the device reads.
 */
final class TimedInputStream extends InputStream {

    /** Source of bytes that returns after a short wait even when nothing arrived. */
    interface Source {
        /**
         * @return bytes read (greater than 0), 0 when nothing arrived within the short wait,
         *         or -1 at end of stream
         */
        int poll(byte[] b, int off, int len) throws IOException;

        /** Bytes readable without waiting. */
        int available();
    }

    private final Source source;
    private final LongSupplier nanoClock;
    private volatile int timeoutMs;

    TimedInputStream(Source source) {
        this(source, System::nanoTime);
    }

    TimedInputStream(Source source, LongSupplier nanoClock) {
        this.source = Objects.requireNonNull(source, "source");
        this.nanoClock = Objects.requireNonNull(nanoClock, "nanoClock");
    }

    /** Read timeout in milliseconds; 0 waits without limit. */
    void setTimeoutMs(int timeoutMs) {
        this.timeoutMs = Math.max(0, timeoutMs);
    }

    int getTimeoutMs() {
        return timeoutMs;
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        int n = read(one, 0, 1);
        return n < 0 ? -1 : (one[0] & 0xFF);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        Objects.checkFromIndexSize(off, len, b.length);
        if (len == 0) {
            return 0;
        }
        long start = nanoClock.getAsLong();
        while (true) {
            int n = source.poll(b, off, len);
            if (n != 0) {
                return n;
            }
            int limit = timeoutMs;
            if (limit > 0 && nanoClock.getAsLong() - start >= limit * 1_000_000L) {
                throw new SocketTimeoutException("No data from the device within " + limit + " ms");
            }
        }
    }

    @Override
    public int available() {
        return source.available();
    }

    @Override
    public void close() {
        /* The owner of the source closes it; SSLSocket teardown must not close the USB link. */
    }
}
