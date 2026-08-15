package fel.cvut.tls;

import CryptoServerJCE.CryptoServerProvider;
import CryptoServerJCE.CryptoServerProviderBuilder;
import fel.cvut.utimaco.HsmGate;
import fel.cvut.utimaco.Pqmi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Objects;

/**
 * JCE/JSSE provider bootstrap, CryptoServer keystore helpers, and HSM ML-DSA signing shim.
 *
 * <p>Routing: CryptoServer (classical) → BC (ML-KEM / verify) → PQMI shim (HSM ML-DSA sign, alternate only).
 */
final class TlsProviders {

    private static final String PQMI_SHIM_NAME = "PqmiShim";
    private static final Object INSTALL_LOCK = new Object();
    private static volatile boolean installed;
    private static CryptoServerProvider cryptoServer;

    private TlsProviders() {
    }

    /**
     * Registers CryptoServer + BC and BC JSSE with PQMI signing alternate.
     * Idempotent. Does not register the PQMI shim in {@link Security}.
     *
     * <p>Logs in one {@link CryptoServerProvider} for the JVM lifetime; all classical HSM
     * JCE ops reuse it. PQMI still opens ephemeral CXI per call — both must use
     * {@link fel.cvut.utimaco.HsmGate}.
     */
    static void install(Pqmi session) throws Exception {
        Objects.requireNonNull(session, "session must not be null");
        synchronized (INSTALL_LOCK) {
            if (installed) {
                return;
            }

            CryptoServerProvider cs = new CryptoServerProviderBuilder()
                    .device(session.device())
                    .timeout(session.timeoutMs())
                    .connectionTimeout(3000)
                    .build();
            cs.loginPassword(session.user(), new String(session.pin()));
            Security.insertProviderAt(cs, 1);
            Security.insertProviderAt(new SigningAuditProvider(cs), 1);
            cryptoServer = cs;

            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.insertProviderAt(new BouncyCastleProvider(), 2);
            }

            if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) != null) {
                Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
            }
            // DefaultJcaJceHelper uses global order (CryptoServer → BC). Do not setProvider().
            JcaTlsCryptoProvider crypto = new JcaTlsCryptoProvider()
                    .setAlternateProvider(new PqmiShimProvider());
            Security.insertProviderAt(new BouncyCastleJsseProvider(false, crypto), 1);

            installed = true;
        }
    }

    static CryptoServerProvider requireCryptoServer() {
        if (cryptoServer == null) {
            throw new IllegalStateException("CryptoServer not installed — call a NodeTls context factory first");
        }
        return cryptoServer;
    }

    static KeyStore openHsmKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("CryptoServer", requireCryptoServer());
        ks.load(null, null);
        return ks;
    }

    record HsmIdentity(PrivateKey key, X509Certificate[] chain) {
    }

    static HsmIdentity loadHsmIdentity(String alias) throws Exception {
        KeyStore hsm = openHsmKeyStore();
        Key key = hsm.getKey(alias, null);
        if (!(key instanceof PrivateKey privateKey)) {
            throw new IllegalStateException("HSM key not found: " + alias
                    + " — import via CertGenerator (option 2)");
        }
        Certificate[] chain = hsm.getCertificateChain(alias);
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("HSM certificate chain not found: " + alias);
        }
        X509Certificate[] x509 = new X509Certificate[chain.length];
        for (int i = 0; i < chain.length; i++) {
            if (!(chain[i] instanceof X509Certificate cert)) {
                throw new IllegalStateException("Non-X509 certificate in HSM chain for: " + alias);
            }
            x509[i] = cert;
        }
        return new HsmIdentity(privateKey, x509);
    }

    /** Opaque PQMI private key — BC rejects it at initSign so the PQMI shim is used. */
    static final class HsmPrivateKey implements PrivateKey {
        private final Pqmi pqmi;

        HsmPrivateKey(Pqmi pqmi) {
            this.pqmi = pqmi;
        }

        Pqmi pqmi() {
            return pqmi;
        }

        @Override
        public String getAlgorithm() {
            return "ML-DSA-44";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }

    /** Key manager for HSM-backed keys (CryptoServer RSA/EC or PQMI {@link HsmPrivateKey}). */
    static final class HsmKeyManager extends X509ExtendedKeyManager {
        private static final String ALIAS = "hsm";
        private final PrivateKey key;
        private final X509Certificate[] chain;

        HsmKeyManager(PrivateKey key, X509Certificate[] chain) {
            this.key = Objects.requireNonNull(key, "key");
            this.chain = chain.clone();
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return matches(keyType) ? new String[]{ALIAS} : null;
        }

        @Override
        public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
            return chooseAlias(keyTypes);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return matches(keyType) ? new String[]{ALIAS} : null;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return matches(keyType) ? ALIAS : null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return matches(keyType) ? ALIAS : null;
        }

        @Override
        public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
            return chooseAlias(keyTypes);
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return ALIAS.equals(alias) ? chain.clone() : null;
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return ALIAS.equals(alias) ? key : null;
        }

        private String chooseAlias(String[] keyTypes) {
            if (keyTypes == null) {
                return null;
            }
            for (String keyType : keyTypes) {
                if (matches(keyType)) {
                    return ALIAS;
                }
            }
            return null;
        }

        private boolean matches(String keyType) {
            if (keyType == null) {
                return false;
            }
            String alg = key.getAlgorithm();
            String kt = keyType.toUpperCase(Locale.ROOT);
            String au = alg.toUpperCase(Locale.ROOT);
            if (kt.equals(au) || au.startsWith(kt) || au.contains(kt)) {
                return true;
            }
            return switch (kt) {
                case "RSA" -> au.contains("RSA");
                case "EC", "ECDSA" -> au.contains("EC");
                case "ML-DSA", "MLDSA44", "ML-DSA-44" -> au.contains("ML-DSA") || au.contains("MLDSA");
                default -> false;
            };
        }
    }

    /** BC JSSE alternate only — not registered via {@link Security#addProvider}. */
    private static final class PqmiShimProvider extends Provider {
        PqmiShimProvider() {
            super(PQMI_SHIM_NAME, "1.0", "HSM ML-DSA signing shim");
            putService(new Service(this, "Signature", "ML-DSA", MlDsaSpi.class.getName(), null, null) {
                @Override
                public Object newInstance(Object ctorParam) {
                    return new MlDsaSpi();
                }
            });
        }
    }

    private static final class MlDsaSpi extends SignatureSpi {
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private Pqmi pqmi;
        private boolean signing;

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            throw new InvalidKeyException("verify not supported");
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            if (!(privateKey instanceof HsmPrivateKey hsmKey)) {
                throw new InvalidKeyException("expected HsmPrivateKey");
            }
            this.pqmi = hsmKey.pqmi();
            buffer.reset();
            signing = true;
        }

        @Override
        protected void engineUpdate(byte b) {
            buffer.write(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) {
            buffer.write(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            if (!signing || pqmi == null) {
                throw new SignatureException("not initialized");
            }
            byte[] message = buffer.toByteArray();
            try {
                byte[] signature = pqmi.sign(message);
                SigningAudit.log(true, "PQMI", "ML-DSA-44", message.length);
                return signature;
            } catch (Exception e) {
                throw new SignatureException("HSM sign failed", e);
            } finally {
                buffer.reset();
            }
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            throw new SignatureException("verify not supported");
        }

        @Override
        @Deprecated
        protected void engineSetParameter(String param, Object value) {
            throw new UnsupportedOperationException();
        }

        @Override
        @Deprecated
        protected Object engineGetParameter(String param) {
            throw new UnsupportedOperationException();
        }
    }

    private static final String[] AUDITED_SIGNATURE_ALGORITHMS = {
            "SHA256withRSA",
            "SHA384withRSA",
            "SHA512withRSA",
            "SHA256withECDSA",
            "SHA384withECDSA",
            "SHA512withECDSA",
    };

    /** Logs classical TLS identity signing before delegating to CryptoServer or BC. */
    private static final class SigningAuditProvider extends Provider {
        SigningAuditProvider(CryptoServerProvider cryptoServer) {
            super("TlsSigningAudit", "1.0", "TLS identity signing audit");
            for (String algorithm : AUDITED_SIGNATURE_ALGORITHMS) {
                putService(new Service(this, "Signature", algorithm, AuditedSignatureSpi.class.getName(),
                        java.util.List.of("Algorithm=" + algorithm), null) {
                    @Override
                    public Object newInstance(Object ctorParam) throws NoSuchAlgorithmException {
                        return new AuditedSignatureSpi(algorithm, cryptoServer);
                    }
                });
            }
        }
    }

    private static final class AuditedSignatureSpi extends SignatureSpi {
        private final String algorithm;
        private final CryptoServerProvider cryptoServer;
        private Signature delegate;
        private boolean hsm;
        private String backend;
        private int messageBytes;

        AuditedSignatureSpi(String algorithm, CryptoServerProvider cryptoServer) {
            this.algorithm = algorithm;
            this.cryptoServer = cryptoServer;
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            messageBytes = 0;
            try {
                delegate = Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
                delegate.initVerify(publicKey);
            } catch (Exception e) {
                throw new InvalidKeyException("verify init failed", e);
            }
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            messageBytes = 0;
            try {
                delegate = Signature.getInstance(algorithm, cryptoServer);
                delegate.initSign(privateKey);
                backend = "CryptoServer";
                hsm = privateKey.getEncoded() == null;
            } catch (InvalidKeyException cryptoServerFailure) {
                try {
                    delegate = Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
                    delegate.initSign(privateKey);
                    backend = "BC";
                    hsm = false;
                } catch (Exception bcFailure) {
                    throw cryptoServerFailure;
                }
            } catch (Exception e) {
                throw new InvalidKeyException("sign init failed", e);
            }
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            messageBytes++;
            delegate.update(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            messageBytes += len;
            delegate.update(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            try {
                byte[] signature = hsm && "CryptoServer".equals(backend)
                        ? HsmGate.call(delegate::sign)
                        : delegate.sign();
                SigningAudit.log(hsm, backend, algorithm, messageBytes);
                return signature;
            } catch (SignatureException e) {
                throw e;
            } catch (Exception e) {
                throw new SignatureException("HSM sign failed", e);
            }
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            return delegate.verify(sigBytes);
        }

        @Override
        @Deprecated
        protected void engineSetParameter(String param, Object value) {
            throw new UnsupportedOperationException();
        }

        @Override
        @Deprecated
        protected Object engineGetParameter(String param) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class SigningAudit {
        private SigningAudit() {
        }

        static void log(boolean hsm, String backend, String algorithm, int messageBytes) {
            if (hsm) {
                System.out.println("[TLS] Identity signing on HSM ("
                        + backend + ", " + algorithm + "), message=" + messageBytes + " bytes");
            } else {
                System.out.println("[TLS] Identity signing NOT on HSM ("
                        + backend + ", " + algorithm + "), message=" + messageBytes + " bytes");
            }
        }
    }
}
