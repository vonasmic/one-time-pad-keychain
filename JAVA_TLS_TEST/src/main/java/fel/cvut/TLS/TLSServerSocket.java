package fel.cvut.TLS;

public class TLSServerSocket {

    static {
        System.loadLibrary("wolf_jni_tls");
    }

    private long nativeHandle;

    public TLSServerSocket(int port) {
        this.nativeHandle = nativeInit(port);
    }

    public TLSSocket accept() {
        long connId = nativeAccept(nativeHandle);
        return new TLSSocket(nativeHandle, connId);
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