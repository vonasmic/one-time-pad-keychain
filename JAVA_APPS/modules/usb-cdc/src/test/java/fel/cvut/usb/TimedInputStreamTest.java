package fel.cvut.usb;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.Deque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class TimedInputStreamTest {

    /** Fake USB link: each poll without data advances the clock by one serial wait (50 ms). */
    private static final class FakeLink implements TimedInputStream.Source {
        final Deque<byte[]> chunks = new ArrayDeque<>();
        long nowNanos;
        int polls;
        boolean ended;
        int emptyPollsBeforeData;

        @Override
        public int poll(byte[] b, int off, int len) {
            polls++;
            if (emptyPollsBeforeData > 0) {
                emptyPollsBeforeData--;
                nowNanos += 50_000_000L;
                return 0;
            }
            byte[] next = chunks.poll();
            if (next != null) {
                int n = Math.min(len, next.length);
                System.arraycopy(next, 0, b, off, n);
                return n;
            }
            if (ended) {
                return -1;
            }
            nowNanos += 50_000_000L;
            return 0;
        }

        @Override
        public int available() {
            byte[] next = chunks.peek();
            return next == null ? 0 : next.length;
        }
    }

    @Test
    void readWithoutDataThrowsSocketTimeoutAfterTheTimeout() {
        FakeLink link = new FakeLink();
        TimedInputStream in = new TimedInputStream(link, () -> link.nowNanos);
        in.setTimeoutMs(100_000);

        SocketTimeoutException ex = assertThrows(SocketTimeoutException.class, () -> in.read(new byte[8], 0, 8));

        assertEquals(100_000_000_000L, link.nowNanos);
        assertTrue(ex.getMessage().contains("100000 ms"), ex.getMessage());
    }

    @Test
    void streamStaysUsableAfterATimeout() throws IOException {
        FakeLink link = new FakeLink();
        TimedInputStream in = new TimedInputStream(link, () -> link.nowNanos);
        in.setTimeoutMs(200);
        assertThrows(SocketTimeoutException.class, () -> in.read(new byte[4], 0, 4));

        link.chunks.add(new byte[] {7, 8});
        byte[] buf = new byte[4];
        assertEquals(2, in.read(buf, 0, 4));
        assertEquals(7, buf[0]);
        assertEquals(8, buf[1]);
    }

    @Test
    void dataBeforeTheTimeoutIsReturned() throws IOException {
        FakeLink link = new FakeLink();
        link.emptyPollsBeforeData = 3;
        link.chunks.add(new byte[] {42});
        TimedInputStream in = new TimedInputStream(link, () -> link.nowNanos);
        in.setTimeoutMs(200);

        assertEquals(42, in.read());
        assertEquals(4, link.polls);
    }

    @Test
    void zeroTimeoutWaitsUntilData() throws IOException {
        FakeLink link = new FakeLink();
        link.emptyPollsBeforeData = 10_000;
        link.chunks.add(new byte[] {1});
        TimedInputStream in = new TimedInputStream(link, () -> link.nowNanos);

        assertEquals(1, in.read());
        assertEquals(10_001, link.polls);
    }

    @Test
    void endOfLinkReadsEndOfStream() throws IOException {
        FakeLink link = new FakeLink();
        link.ended = true;
        TimedInputStream in = new TimedInputStream(link, () -> link.nowNanos);
        in.setTimeoutMs(100);

        assertEquals(-1, in.read(new byte[4], 0, 4));
    }

    @Test
    void streamSocketSoTimeoutSetsTheReadTimeout() throws IOException {
        FakeLink link = new FakeLink();
        TimedInputStream in = new TimedInputStream(link, () -> link.nowNanos);
        StreamSocket socket = new StreamSocket(in, new ByteArrayOutputStream());

        socket.setSoTimeout(900_000);

        assertEquals(900_000, in.getTimeoutMs());
        assertThrows(SocketTimeoutException.class, () -> socket.getInputStream().read(new byte[1], 0, 1));
        assertEquals(900_000_000_000L, link.nowNanos);
    }

    @Test
    void sslSocketSoTimeoutReachesTheUsbStream() throws Exception {
        FakeLink link = new FakeLink();
        TimedInputStream in = new TimedInputStream(link, () -> link.nowNanos);
        StreamSocket socket = new StreamSocket(in, new ByteArrayOutputStream());
        SSLSocket ssl = (SSLSocket) SSLContext.getDefault().getSocketFactory()
                .createSocket(socket, "device", 0, false);

        ssl.setSoTimeout(100_000);

        assertEquals(100_000, in.getTimeoutMs());
    }
}
