package fel.cvut.TLS;

public final class TLSSocket implements AutoCloseable {

    private final long serverHandle;
    private final long connId;

    TLSSocket(long serverHandle, long connId) {
        this.serverHandle = serverHandle;
        this.connId = connId;
    }

    public byte[] read() {
        return nativeRead(serverHandle, connId);
    }

    public void write(byte[] data) {
        nativeWrite(serverHandle, connId, data);
    }

    @Override
    public void close() {
        nativeConnClose(serverHandle, connId);
    }

    private static native byte[] nativeRead(long serverHandle, long connId);

    private static native void nativeWrite(long serverHandle, long connId, byte[] data);

    private static native void nativeConnClose(long serverHandle, long connId);
}
