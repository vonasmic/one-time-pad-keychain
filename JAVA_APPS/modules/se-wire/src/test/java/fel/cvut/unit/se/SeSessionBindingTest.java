package fel.cvut.unit.se;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeCerts;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeSessionBinding;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Tag("unit")
class SeSessionBindingTest {

    private static final SecureRandom RNG = new SecureRandom();


    @Test
    void wrapTrustManagersWrapsOnlyExtendedManagers() {
        assertThrows(NullPointerException.class, () -> SeSessionBinding.wrapTrustManagers(null));
        X509ExtendedTrustManager ext = mock(X509ExtendedTrustManager.class);
        TrustManager plain = mock(TrustManager.class);
        TrustManager[] original = {ext, plain};

        TrustManager[] wrapped = SeSessionBinding.wrapTrustManagers(original);

        assertNotSame(original, wrapped);
        assertSame(ext, original[0], "input array must not be mutated");
        assertNotSame(ext, wrapped[0]);
        assertInstanceOf(X509ExtendedTrustManager.class, wrapped[0]);
        assertSame(plain, wrapped[1]);
    }

    @Test
    void exportingTrustManagerDelegatesEveryCheck() throws Exception {
        X509ExtendedTrustManager delegate = mock(X509ExtendedTrustManager.class);
        X509Certificate[] issuers = new X509Certificate[0];
        when(delegate.getAcceptedIssuers()).thenReturn(issuers);
        X509ExtendedTrustManager tm = wrap(delegate);
        X509Certificate[] chain = new X509Certificate[0];
        Socket plainSocket = new Socket();
        SSLEngine engine = mock(SSLEngine.class);

        tm.checkClientTrusted(chain, "EC", plainSocket);
        tm.checkServerTrusted(chain, "EC", plainSocket);
        tm.checkClientTrusted(chain, "EC", engine);
        tm.checkServerTrusted(chain, "EC", engine);
        tm.checkClientTrusted(chain, "EC");
        tm.checkServerTrusted(chain, "EC");

        verify(delegate).checkClientTrusted(chain, "EC", plainSocket);
        verify(delegate).checkServerTrusted(chain, "EC", plainSocket);
        verify(delegate).checkClientTrusted(chain, "EC", engine);
        verify(delegate).checkServerTrusted(chain, "EC", engine);
        verify(delegate).checkClientTrusted(chain, "EC");
        verify(delegate).checkServerTrusted(chain, "EC");
        assertSame(issuers, tm.getAcceptedIssuers());
        plainSocket.close();
    }

    @Test
    void clientCheckOnNonBcSocketRecordsExportFailureForAttachedExporter() throws Exception {
        X509ExtendedTrustManager tm = wrap(mock(X509ExtendedTrustManager.class));
        SSLSocket socket = mock(SSLSocket.class);
        SeSessionBinding.HandshakeExporter exporter = new SeSessionBinding.HandshakeExporter();
        exporter.attach(socket);

        tm.checkClientTrusted(new X509Certificate[0], "EC", socket);

        IOException ex = assertThrows(IOException.class, exporter::require);
        assertTrue(ex.getMessage().contains("tls-exporter export failed"), ex.getMessage());
        exporter.detach(socket);
    }

    @Test
    void rejectedClientCertDoesNotCaptureExporter() throws Exception {
        X509ExtendedTrustManager delegate = mock(X509ExtendedTrustManager.class);
        doThrow(new CertificateException("untrusted"))
                .when(delegate).checkClientTrusted(any(X509Certificate[].class), anyString(), any(Socket.class));
        X509ExtendedTrustManager tm = wrap(delegate);
        SSLSocket socket = mock(SSLSocket.class);
        SeSessionBinding.HandshakeExporter exporter = new SeSessionBinding.HandshakeExporter();
        exporter.attach(socket);

        assertThrows(CertificateException.class, () -> tm.checkClientTrusted(new X509Certificate[0], "EC", socket));
        IOException ex = assertThrows(IOException.class, exporter::require);
        assertTrue(ex.getMessage().contains("not captured"));
        exporter.detach(socket);
    }

    @Test
    void peerTlsSpkiRejectsMissingOrUnverifiedPeers() throws Exception {
        SSLSession none = mock(SSLSession.class);
        when(none.getPeerCertificates()).thenReturn(new Certificate[0]);
        assertThrows(IOException.class, () -> SeSessionBinding.peerTlsSpki(none));

        SSLSession nul = mock(SSLSession.class);
        when(nul.getPeerCertificates()).thenReturn(null);
        assertThrows(IOException.class, () -> SeSessionBinding.peerTlsSpki(nul));

        SSLSession notX509 = mock(SSLSession.class);
        when(notX509.getPeerCertificates()).thenReturn(new Certificate[] {mock(Certificate.class)});
        IOException ex = assertThrows(IOException.class, () -> SeSessionBinding.peerTlsSpki(notX509));
        assertTrue(ex.getMessage().contains("X.509"));

        SSLSession unverified = mock(SSLSession.class);
        when(unverified.getPeerCertificates()).thenThrow(new SSLPeerUnverifiedException("no"));
        IOException wrapped = assertThrows(IOException.class, () -> SeSessionBinding.peerTlsSpki(unverified));
        assertInstanceOf(SSLPeerUnverifiedException.class, wrapped.getCause());
    }

    @Test
    void peerTlsSpkiReturnsRawSubjectPublicKeyBits() throws Exception {
        X509Certificate cert = selfSignedEcCert();
        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(new Certificate[] {cert});
        byte[] spki = SeSessionBinding.peerTlsSpki(session);
        assertArrayEquals(SeCerts.rawSubjectPublicKeyBits(cert), spki);
        assertEquals(65, spki.length, "uncompressed P-256 point");
    }

    @Test
    void verifyAcceptsValidBindingAndRejectsTampering() throws Exception {
        X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
        ECDomainParameters domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(domain, RNG));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        ECPublicKeyParameters pub = (ECPublicKeyParameters) kp.getPublic();
        byte[] uncompressed = pub.getQ().getEncoded(false);
        byte[] eccPub = java.util.Arrays.copyOfRange(uncompressed, 1, 65);

        byte[] spki = new byte[65];
        RNG.nextBytes(spki);
        byte[] exporter = new byte[SeConstants.EXPORTER_LEN];
        RNG.nextBytes(exporter);
        byte[] clientHash = SeBytes.sha384(SeBytes.concat(spki, eccPub));
        byte[] digest = SeBytes.sha384(SeBytes.concat(clientHash, exporter));
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, (ECPrivateKeyParameters) kp.getPrivate());
        BigInteger[] rs = signer.generateSignature(digest);
        byte[] sig = SeBytes.concat(fixed32(rs[0]), fixed32(rs[1]));

        assertDoesNotThrow(() -> SeSessionBinding.verify(spki, exporter, eccPub, clientHash, sig));

        byte[] otherExporter = exporter.clone();
        otherExporter[0] ^= 1;
        IOException badSig = assertThrows(IOException.class,
                () -> SeSessionBinding.verify(spki, otherExporter, eccPub, clientHash, sig));
        assertTrue(badSig.getMessage().contains("signature"));

        byte[] otherSpki = spki.clone();
        otherSpki[5] ^= 1;
        IOException badHash = assertThrows(IOException.class,
                () -> SeSessionBinding.verify(otherSpki, exporter, eccPub, clientHash, sig));
        assertTrue(badHash.getMessage().contains("client_hash"));

        assertThrows(IllegalArgumentException.class,
                () -> SeSessionBinding.verify(spki, new byte[16], eccPub, clientHash, sig));
    }

    private static X509ExtendedTrustManager wrap(X509ExtendedTrustManager delegate) {
        return (X509ExtendedTrustManager) SeSessionBinding.wrapTrustManagers(new TrustManager[] {delegate})[0];
    }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    private static X509Certificate selfSignedEcCert() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=binding-test");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + 86_400_000L),
                name, kp.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate())));
    }
}