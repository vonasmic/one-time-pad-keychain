package fel.cvut.TLS;

final class NativeTlsLibrary {
    static {
        System.loadLibrary("wolf_jni_tls");
    }

    private NativeTlsLibrary() {
    }

    static void ensureLoaded() {
    }
}
