package fel.cvut.TLS;

public class TLSSocket {

    private long serverHandle;
    private long connId;

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

    public void close() {
        nativeConnClose(serverHandle, connId);
    }

    /* ===== JNI ===== */
    private native byte[] nativeRead(long serverHandle, long connId);
    private native void nativeWrite(long serverHandle, long connId, byte[] data);
    private native void nativeConnClose(long serverHandle, long connId);
}