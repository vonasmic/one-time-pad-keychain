package fel.cvut.se;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsContext;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * TLS session binding checks for the SE uplink: exporter, client_hash, ECDSA signature.
 *
 * <p>RFC 9266 {@code tls-exporter}. BC 1.84 wipes {@code exporter_master_secret} after
 * handshake-complete, and JSSE {@code HandshakeCompletedListener} runs on another thread
 * after that. Capture instead from the trust manager (same thread, client cert already
 * verified, exporter secret already derived).
 */
public final class SeSessionBinding {

    private static final Map<SSLSocket, HandshakeExporter> PENDING =
            Collections.synchronizedMap(new IdentityHashMap<>());

    private SeSessionBinding() {
    }

    /**
     * Captures {@link SeConstants#CHANNEL_BINDING} during client-cert verification.
     * Attach before {@link SSLSocket#startHandshake()}.
     */
    public static final class HandshakeExporter {
        private volatile byte[] material;
        private volatile IOException error;

        public void attach(SSLSocket socket) {
            Objects.requireNonNull(socket, "socket");
            PENDING.put(socket, this);
        }

        public byte[] require() throws IOException {
            if (error != null) {
                throw error;
            }
            if (material == null) {
                throw new IOException("TLS exporter was not captured at handshake complete");
            }
            return material;
        }

        public void detach(SSLSocket socket) {
            if (socket != null) {
                PENDING.remove(socket);
            }
        }
    }

    /** Command-server SSLContext only: export during {@code checkClientTrusted}. */
    public static TrustManager[] wrapTrustManagers(TrustManager[] managers) {
        Objects.requireNonNull(managers, "managers");
        TrustManager[] wrapped = managers.clone();
        for (int i = 0; i < wrapped.length; i++) {
            if (wrapped[i] instanceof X509ExtendedTrustManager ext) {
                wrapped[i] = new ExportingTrustManager(ext);
            }
        }
        return wrapped;
    }

    /**
     * Raw {@code subjectPublicKey} bits, not the SPKI DER: the firmware hashes
     * the enrolled device-cert SPKI, which {@code PeerCertHash} strips down to
     * the BIT STRING payload.
     */
    public static byte[] peerTlsSpki(SSLSession session) throws IOException {
        try {
            Certificate[] chain = session.getPeerCertificates();
            if (chain == null || chain.length == 0) {
                throw new IOException("No peer certificate on TLS session");
            }
            if (!(chain[0] instanceof X509Certificate x509)) {
                throw new IOException("Peer certificate is not X.509");
            }
            ASN1BitString bits = SubjectPublicKeyInfo
                    .getInstance(x509.getPublicKey().getEncoded())
                    .getPublicKeyData();
            if (bits == null || bits.getBytes().length == 0) {
                throw new IOException("Peer certificate has no subjectPublicKey");
            }
            return bits.getBytes();
        } catch (SSLPeerUnverifiedException ex) {
            throw new IOException("Peer not verified; cannot read TLS SPKI", ex);
        }
    }

    /**
     * Verifies {@code client_hash = SHA384(spki || ecc_pub)} over the raw SPKI bits from
     * {@link #peerTlsSpki} and Tropic ECDSA over {@code SHA384(client_hash || exporter)}.
     */
    public static void verify(
            byte[] peerTlsSpki,
            byte[] exporter,
            byte[] eccPub,
            byte[] clientHash,
            byte[] sessionSig
    ) throws IOException {
        if (exporter.length != SeConstants.EXPORTER_LEN) {
            throw new IllegalArgumentException("exporter must be " + SeConstants.EXPORTER_LEN + " bytes");
        }
        byte[] expectedClientHash = SeBytes.sha384(SeBytes.concat(peerTlsSpki, eccPub));
        if (!MessageDigest.isEqual(expectedClientHash, clientHash)) {
            throw new IOException("client_hash mismatch (TLS SPKI || ecc_pub)");
        }
        byte[] toSign = SeBytes.sha384(SeBytes.concat(clientHash, exporter));
        if (!verifyEcdsaRaw(eccPub, toSign, sessionSig)) {
            throw new IOException("Session ECDSA signature verification failed");
        }
    }

    static void captureFromSocket(Socket socket) {
        if (!(socket instanceof SSLSocket ssl)) {
            return;
        }
        HandshakeExporter exporter = PENDING.remove(ssl);
        if (exporter == null) {
            return;
        }
        try {
            byte[] material = exportFromHandshake(ssl);
            if (material == null || material.length != SeConstants.EXPORTER_LEN) {
                throw new IOException("TLS tls-exporter unavailable or unexpected length");
            }
            exporter.material = material;
        } catch (IOException e) {
            exporter.error = e;
        } catch (ReflectiveOperationException e) {
            exporter.error = new IOException("TLS tls-exporter export failed", e);
        } catch (RuntimeException e) {
            exporter.error = new IOException("TLS channel-binding export failed", e);
        }
    }

    /** RFC 9266 through BC's own exporter, run while the handshake secret still exists. */
    private static byte[] exportFromHandshake(SSLSocket socket) throws ReflectiveOperationException, IOException {
        /* ProvSSLSocket and ProvTlsPeer are package-private; TlsContext is public API. */
        Object peer = declaredField(socket.getClass(), "protocolPeer").get(socket);
        if (peer == null) {
            throw new IOException("TLS peer not available");
        }
        Method getTlsContext = peer.getClass().getMethod("getTlsContext");
        getTlsContext.setAccessible(true);
        TlsContext ctx = (TlsContext) getTlsContext.invoke(peer);

        SecurityParameters handshake = ctx.getSecurityParametersHandshake();
        if (handshake == null || handshake.getExporterMasterSecret() == null) {
            throw new IOException("TLS exporter master secret not available");
        }

        /*
         * The exporter reads the connection parameters, which BC only publishes in
         * notifyHandshakeComplete and then wipes. Publish the very object it is about
         * to install there, and put it back so the socket stays mid-handshake.
         */
        Field connection = declaredField(ctx.getClass(), "securityParametersConnection");
        connection.set(ctx, handshake);
        try {
            return ctx.exportChannelBinding(ChannelBinding.tls_exporter);
        } finally {
            connection.set(ctx, null);
        }
    }

    private static Field declaredField(Class<?> owner, String name) throws NoSuchFieldException {
        for (Class<?> type = owner; type != null; type = type.getSuperclass()) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException ignored) {
                // keep walking
            }
        }
        throw new NoSuchFieldException(name);
    }

    /**
     * TROPIC01 signs the leftmost 32 bytes of the SHA-384 digest, because its ECDSA command
     * takes exactly one 32-byte input. {@link ECDSASigner} derives {@code e} from the leftmost
     * bits of whatever digest it is given (FIPS 186-4 §6.4), so the full 48 bytes verify.
     */
    private static boolean verifyEcdsaRaw(byte[] xy64, byte[] digest, byte[] sig64) {
        X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
        ECDomainParameters domain = new ECDomainParameters(
                curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(xy64, 0, uncompressed, 1, 64);
        ECPoint q = curve.getCurve().decodePoint(uncompressed);
        ECPublicKeyParameters pub = new ECPublicKeyParameters(q, domain);

        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig64, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, pub);
        return signer.verifySignature(digest, r, s);
    }

    /**
     * A JSSE {@link X509ExtendedTrustManager}: BC imports it through the wrapper that
     * still passes the {@link Socket}, which is what identifies the session.
     */
    private static final class ExportingTrustManager extends X509ExtendedTrustManager {
        private final X509ExtendedTrustManager delegate;

        private ExportingTrustManager(X509ExtendedTrustManager delegate) {
            this.delegate = delegate;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            delegate.checkClientTrusted(chain, authType, socket);
            captureFromSocket(socket);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            delegate.checkServerTrusted(chain, authType, socket);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            delegate.checkClientTrusted(chain, authType, engine);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            delegate.checkServerTrusted(chain, authType, engine);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }
}
