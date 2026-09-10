package fel.cvut.usb;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Objects;

/**
 * Connected {@link Socket} whose I/O is an existing stream pair (USB CDC TLS bytes).
 */
public final class StreamSocket extends Socket {

    private final InputStream in;
    private final OutputStream out;
    private volatile boolean closed;
    private volatile int soTimeoutMs;

    public StreamSocket(InputStream in, OutputStream out) {
        this.in = Objects.requireNonNull(in, "in");
        this.out = Objects.requireNonNull(out, "out");
    }

    @Override
    public InputStream getInputStream() throws IOException {
        ensureOpen();
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        ensureOpen();
        return out;
    }

    @Override
    public boolean isConnected() {
        return !closed;
    }

    @Override
    public boolean isBound() {
        return !closed;
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public boolean isInputShutdown() {
        return closed;
    }

    @Override
    public boolean isOutputShutdown() {
        return closed;
    }

    @Override
    public InetAddress getInetAddress() {
        return InetAddress.getLoopbackAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return InetAddress.getLoopbackAddress();
    }

    @Override
    public int getPort() {
        return 1;
    }

    @Override
    public int getLocalPort() {
        return 1;
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), 1);
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), 1);
    }

    @Override
    public void setTcpNoDelay(boolean on) {
    }

    @Override
    public boolean getTcpNoDelay() {
        return true;
    }

    @Override
    public void setSoLinger(boolean on, int linger) {
    }

    @Override
    public int getSoLinger() {
        return -1;
    }

    @Override
    public void setSoTimeout(int timeout) {
        soTimeoutMs = Math.max(0, timeout);
    }

    @Override
    public int getSoTimeout() {
        return soTimeoutMs;
    }

    @Override
    public void setKeepAlive(boolean on) {
    }

    @Override
    public boolean getKeepAlive() {
        return false;
    }

    @Override
    public void setOOBInline(boolean on) {
    }

    @Override
    public boolean getOOBInline() {
        return false;
    }

    @Override
    public void setSendBufferSize(int size) {
    }

    @Override
    public int getSendBufferSize() {
        return 8192;
    }

    @Override
    public void setReceiveBufferSize(int size) {
    }

    @Override
    public int getReceiveBufferSize() {
        return 8192;
    }

    @Override
    public void setReuseAddress(boolean on) {
    }

    @Override
    public boolean getReuseAddress() {
        return false;
    }

    @Override
    public void setTrafficClass(int tc) {
    }

    @Override
    public int getTrafficClass() {
        return 0;
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        throw new SocketException("Urgent data is not supported");
    }

    @Override
    public void shutdownInput() {
    }

    @Override
    public void shutdownOutput() {
    }

    @Override
    public synchronized void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        IOException first = null;
        try {
            in.close();
        } catch (IOException e) {
            first = e;
        }
        try {
            out.close();
        } catch (IOException e) {
            if (first == null) {
                first = e;
            }
        }
        if (first != null) {
            throw first;
        }
    }

    private void ensureOpen() throws SocketException {
        if (closed) {
            throw new SocketException("Socket is closed");
        }
    }
}
