package fel.cvut.TLS;

public final class NativeTlsServer implements AutoCloseable {

    static {
        NativeTlsLibrary.ensureLoaded();
    }

    private final long handle;

    public NativeTlsServer(int port) {
        handle = nativeInit(port);
    }

    public TLSSocket accept() {
        long connId = nativeAccept(handle);
        return new TLSSocket(handle, connId);
    }

    @Override
    public void close() {
        nativeClose(handle);
    }

    private static native long nativeInit(int port);

    private static native long nativeAccept(long handle);

    private static native void nativeClose(long handle);
}
