package fel.cvut.TLS;

public class NativeTlsServer {

    static {
        NativeTlsLibrary.ensureLoaded();
    }

    private long nativeHandle;

    public NativeTlsServer(int port) {
        this.nativeHandle = nativeInit(port);
    }

    public NativeTlsSocket accept() {
        long connId = nativeAccept(nativeHandle);
        return new NativeTlsSocket(nativeHandle, connId);
    }

    public void close() {
        nativeClose(nativeHandle);
        nativeHandle = 0;
    }

    /* ===== JNI ===== */
    private native long nativeInit(int port);
    private native long nativeAccept(long handle);
    private native void nativeClose(long handle);
}