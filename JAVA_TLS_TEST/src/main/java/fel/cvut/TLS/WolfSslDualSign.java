package fel.cvut.TLS;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.provider.jsse.WolfSSLEngineHelper;
import com.wolfssl.provider.jsse.WolfSSLSocket;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Objects;

public final class WolfSslDualSign {
    private static final int WOLFSSL_CKS_SIGSPEC_BOTH = 0x0003;

    static {
        NativeTlsLibrary.ensureLoaded();
    }

    private WolfSslDualSign() {
    }

    public static void configureServerDualSign(SSLContext sslContext, String altPrivateKeyPath) {
        Objects.requireNonNull(sslContext, "sslContext must not be null");
        Objects.requireNonNull(altPrivateKeyPath, "altPrivateKeyPath must not be null");

        long ctxPtr = extractNativeCtxPointer(sslContext);
        nativeConfigureServerDualSign(ctxPtr, altPrivateKeyPath, WOLFSSL_CKS_SIGSPEC_BOTH);
    }

    public static boolean isHybridNegotiated(long x509StorePtr) {
        if (x509StorePtr == 0L) {
            throw new WolfSslDualSignException("WOLFSSL_X509_STORE_CTX pointer is zero");
        }
        return nativeIsDualSignatureNegotiated(x509StorePtr);
    }

    public static boolean isHybridNegotiatedOnConnection(SSLSocket socket) {
        return nativeIsDualSignatureNegotiatedOnSsl(extractNativeSslPointer(socket));
    }

    public static void requireHybridNegotiatedOnConnection(SSLSocket socket) {
        if (!isHybridNegotiatedOnConnection(socket)) {
            throw new WolfSslDualSignException(
                "Dual signature negotiation (CKS BOTH) was not confirmed on connection");
        }
    }

    public static void startServerHandshake(SSLSocket socket) throws IOException {
        if (!(socket instanceof WolfSSLSocket wolfSocket)) {
            throw new WolfSslDualSignException(
                "Expected wolfJSSE SSLSocket, got: " + socket.getClass().getName());
        }

        try {
            WolfSSLEngineHelper helper = extractEngineHelper(wolfSocket);
            Field handshakeInitCalledField =
                WolfSSLSocket.class.getDeclaredField("handshakeInitCalled");
            handshakeInitCalledField.setAccessible(true);

            synchronized (extractHandshakeLock(wolfSocket)) {
                if (!handshakeInitCalledField.getBoolean(wolfSocket)) {
                    Method initHandshake = WolfSSLEngineHelper.class.getDeclaredMethod(
                        "initHandshake", SSLSocket.class);
                    initHandshake.setAccessible(true);
                    initHandshake.invoke(helper, wolfSocket);
                    handshakeInitCalledField.setBoolean(wolfSocket, true);
                }
            }

            int verifyMask = extractVerifyMask(helper) |
                WolfSSL.SSL_VERIFY_PEER |
                WolfSSL.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

            nativeInstallDualSignVerifyOnSsl(extractNativeSslPointer(wolfSocket), verifyMask);
            wolfSocket.startHandshake();
        } catch (WolfSslDualSignException e) {
            throw e;
        } catch (ReflectiveOperationException e) {
            throw new WolfSslDualSignException("Failed to run dual-sign handshake", e);
        }
    }

    private static WolfSSLEngineHelper extractEngineHelper(WolfSSLSocket socket)
            throws ReflectiveOperationException {
        Field helperField = WolfSSLSocket.class.getDeclaredField("EngineHelper");
        helperField.setAccessible(true);
        return (WolfSSLEngineHelper) helperField.get(socket);
    }

    private static Object extractHandshakeLock(WolfSSLSocket socket)
            throws ReflectiveOperationException {
        Field handshakeLockField = WolfSSLSocket.class.getDeclaredField("handshakeLock");
        handshakeLockField.setAccessible(true);
        return handshakeLockField.get(socket);
    }

    private static int extractVerifyMask(WolfSSLEngineHelper helper)
            throws ReflectiveOperationException {
        Field verifyMaskField = WolfSSLEngineHelper.class.getDeclaredField("verifyMask");
        verifyMaskField.setAccessible(true);
        return verifyMaskField.getInt(helper);
    }

    private static long extractNativeSslPointer(SSLSocket socket) {
        try {
            WolfSSLSession ssl = extractWolfSslSession(socket);
            Field sslPtrField = WolfSSLSession.class.getDeclaredField("sslPtr");
            sslPtrField.setAccessible(true);
            Object ptr = sslPtrField.get(ssl);
            if (!(ptr instanceof Long nativePtr)) {
                throw new WolfSslDualSignException(
                    "Unexpected WOLFSSL pointer type: " + ptr);
            }
            if (nativePtr == 0L) {
                throw new WolfSslDualSignException("Extracted WOLFSSL pointer is zero");
            }
            return nativePtr;
        } catch (WolfSslDualSignException e) {
            throw e;
        } catch (ReflectiveOperationException e) {
            throw new WolfSslDualSignException("Failed to extract native WOLFSSL pointer", e);
        }
    }

    private static WolfSSLSession extractWolfSslSession(SSLSocket socket) {
        if (!(socket instanceof WolfSSLSocket wolfSocket)) {
            throw new WolfSslDualSignException(
                "Expected wolfJSSE SSLSocket, got: " + socket.getClass().getName());
        }

        try {
            Field sslField = WolfSSLSocket.class.getDeclaredField("ssl");
            sslField.setAccessible(true);
            WolfSSLSession ssl = (WolfSSLSession) sslField.get(wolfSocket);
            if (ssl == null) {
                throw new WolfSslDualSignException("wolfJSSE session is null");
            }
            return ssl;
        } catch (WolfSslDualSignException e) {
            throw e;
        } catch (ReflectiveOperationException e) {
            throw new WolfSslDualSignException("Failed to extract wolfJSSE session", e);
        }
    }

    private static long extractNativeCtxPointer(SSLContext sslContext) {
        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        String className = factory.getClass().getName();
        if (!"com.wolfssl.provider.jsse.WolfSSLServerSocketFactory".equals(className)) {
            throw new WolfSslDualSignException("Expected wolfJSSE factory, got: " + className);
        }

        try {
            Field ctxField = factory.getClass().getDeclaredField("ctx");
            ctxField.setAccessible(true);
            Object wolfCtx = ctxField.get(factory);
            if (wolfCtx == null) {
                throw new WolfSslDualSignException("wolfJSSE context is null");
            }

            Method getContextPtr = wolfCtx.getClass().getDeclaredMethod("getContextPtr");
            getContextPtr.setAccessible(true);

            Object ptr = getContextPtr.invoke(wolfCtx);
            if (!(ptr instanceof Long nativePtr)) {
                throw new WolfSslDualSignException("Unexpected WOLFSSL_CTX pointer type: " + ptr);
            }
            if (nativePtr == 0L) {
                throw new WolfSslDualSignException("Extracted WOLFSSL_CTX pointer is zero");
            }
            return nativePtr;
        } catch (WolfSslDualSignException e) {
            throw e;
        } catch (Exception e) {
            throw new WolfSslDualSignException("Failed to extract native WOLFSSL_CTX pointer", e);
        }
    }

    private static native void nativeConfigureServerDualSign(
            long ctxPtr,
            String altPrivateKeyPath,
            int sigSpec
    );

    private static native boolean nativeIsDualSignatureNegotiated(long x509StorePtr);

    private static native boolean nativeIsDualSignatureNegotiatedOnSsl(long sslPtr);

    private static native void nativeInstallDualSignVerifyOnSsl(long sslPtr, int verifyMode);
}
