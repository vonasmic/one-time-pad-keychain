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
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
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
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * JCE/JSSE provider bootstrap, CryptoServer keystore helpers, and HSM signing.
 *
 * <p>Global {@link Security} order is JSSE → software Mac (BC) → CryptoServer → BC. Unscoped
 * {@code Mac.getInstance} must not hit CryptoServer: PostgreSQL SCRAM uses a software
 * {@code SecretKeySpec("HmacSHA256")}, and {@code CryptoServerMac} then fails with
 * {@code / by zero} (never sets {@code blockSize} for non-AES/DES keys). TLS identity signing
 * does not use that list: the JSSE helper is pinned to BC, and {@link HsmSigningProvider} is
 * the JSSE alternate (never registered globally). BC {@code initSign} on an HSM key throws
 * {@link InvalidKeyException}; JSSE then uses the alternate (CryptoServer + {@link HsmGate},
 * or PQMI for ML-DSA).
 */
final class TlsProviders {

    private static final Object INSTALL_LOCK = new Object();
    private static volatile boolean installed;
    private static CryptoServerProvider cryptoServer;

    private TlsProviders() {
    }

    /**
     * Registers BC JSSE, BC Mac preference, CryptoServer (HSM-first for other unscoped JCE),
     * and Bouncy Castle. Idempotent. Does not register the HSM signing shim in {@link Security}.
     */
    static void install(Pqmi session) throws Exception {
        Objects.requireNonNull(session, "session must not be null");
        synchronized (INSTALL_LOCK) {
            if (installed) {
                return;
            }

            CryptoServerProvider cs = loggedInCryptoServer(session);
            cryptoServer = cs;
            Provider bc = new BouncyCastleProvider();

            // Highest priority first:
            //   1. BC JSSE        — TLS engine; helper = BC, alternate = HsmSigningProvider
            //   2. Software Mac   — BC Mac so JDBC SCRAM is not routed to CryptoServer
            //   3. CryptoServer   — HSM-first for unscoped JCE (AES, KeyGen, …)
            //   4. Bouncy Castle  — ML-KEM, verify, PEM/PKCS#12
            installOrdered(List.of(
                    bcJsseWithHsmAlternate(cs, bc),
                    softwareMacPreferred(bc),
                    cs,
                    bc));

            installed = true;
        }
    }

    private static CryptoServerProvider loggedInCryptoServer(Pqmi session) throws Exception {
        CryptoServerProvider cs = new CryptoServerProviderBuilder()
                .device(session.device())
                .timeout(session.timeoutMs())
                .connectionTimeout(3000)
                .build();
        cs.loginPassword(session.user(), new String(session.pin()));
        return cs;
    }

    /**
     * Advertises only {@code Mac} from BC, ahead of CryptoServer. Explicit
     * {@code Mac.getInstance(alg, cryptoServer)} still uses the HSM.
     */
    private static Provider softwareMacPreferred(Provider bc) {
        return new SoftwareMacProvider(bc);
    }

    private static final class SoftwareMacProvider extends Provider {
        SoftwareMacProvider(Provider bc) {
            super("SoftwareMac", "1.0",
                    "BC HMAC so unscoped Mac is not served by CryptoServer");
            for (Service service : bc.getServices()) {
                if (!"Mac".equals(service.getType())) {
                    continue;
                }
                Service backend = service;
                putService(new Service(this, backend.getType(), backend.getAlgorithm(),
                        backend.getClassName(), null, null) {
                    @Override
                    public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
                        return backend.newInstance(constructorParameter);
                    }
                });
            }
        }
    }

    private static BouncyCastleJsseProvider bcJsseWithHsmAlternate(CryptoServerProvider cs, Provider bc) {
        // Pin the default helper to BC. If CryptoServer is first in Security, JSSE would
        // initSign HSM keys on Ultimaco directly and never call the alternate (no HsmGate).
        JcaTlsCryptoProvider crypto = new JcaTlsCryptoProvider()
                .setProvider(bc)
                .setAlternateProvider(HsmSigningProvider.jsseAlternate(cs));
        return new BouncyCastleJsseProvider(false, crypto);
    }

    /**
     * Installs providers so {@link Security} order matches {@code
     * providersHighestPriorityFirst}. Existing providers with the same name are removed first.
     */
    private static void installOrdered(List<Provider> providersHighestPriorityFirst) {
        for (Provider provider : providersHighestPriorityFirst) {
            Security.removeProvider(provider.getName());
        }
        for (int i = providersHighestPriorityFirst.size() - 1; i >= 0; i--) {
            Security.insertProviderAt(providersHighestPriorityFirst.get(i), 1);
        }
    }

    static CryptoServerProvider requireCryptoServer() {
        if (cryptoServer == null) {
            throw new IllegalStateException("CryptoServer not installed — call NodeTls.install first");
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

    /**
     * JSSE alternate for TLS identity signing. Never registered in {@link Security}.
     * Classical sign → CryptoServer + {@link HsmGate}; ML-DSA sign → PQMI.
     */
    private static final class HsmSigningProvider extends Provider {
        private HsmSigningProvider() {
            super("TlsHsmAlternate", "1.0", "JSSE alternate for HSM signing");
        }

        static HsmSigningProvider jsseAlternate(CryptoServerProvider cs) {
            HsmSigningProvider provider = new HsmSigningProvider();
            provider.putService(new Service(provider, "Signature", "ML-DSA", MlDsaSpi.class.getName(), null, null) {
                @Override
                public Object newInstance(Object ctorParam) {
                    return new MlDsaSpi();
                }
            });
            for (HsmSignatureAlgorithm algorithm : HSM_SIGNATURE_ALGORITHMS) {
                provider.putService(new Service(
                        provider,
                        "Signature",
                        algorithm.advertisedName(),
                        HsmSignatureSpi.class.getName(),
                        algorithm.aliases(),
                        null) {
                    @Override
                    public Object newInstance(Object ctorParam) {
                        return new HsmSignatureSpi(algorithm, cs);
                    }
                });
            }
            return provider;
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
                SigningAudit.log("PQMI", "ML-DSA-44", message.length);
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

    /**
     * Classical TLS identity algorithms advertised by {@link HsmSigningProvider}.
     * BC JSSE asks for {@code SHA256WITHRSAANDMGF1} then falls back to
     * {@code SHA256WITHRSASSA-PSS}; CryptoServer registers the latter form.
     */
    private record HsmSignatureAlgorithm(String advertisedName, String cryptoServerName, List<String> aliases) {
        static HsmSignatureAlgorithm pkcs1(String name) {
            return new HsmSignatureAlgorithm(name, name, List.of());
        }

        static HsmSignatureAlgorithm rsaPss(String digest) {
            String cryptoServerName = digest + "withRSASSA-PSS";
            return new HsmSignatureAlgorithm(
                    cryptoServerName,
                    cryptoServerName,
                    List.of(
                            digest + "WITHRSASSA-PSS",
                            digest + "withRSAANDMGF1",
                            digest + "WITHRSAANDMGF1"
                    )
            );
        }
    }

    private static final HsmSignatureAlgorithm[] HSM_SIGNATURE_ALGORITHMS = {
            HsmSignatureAlgorithm.pkcs1("SHA256withRSA"),
            HsmSignatureAlgorithm.pkcs1("SHA384withRSA"),
            HsmSignatureAlgorithm.pkcs1("SHA512withRSA"),
            HsmSignatureAlgorithm.rsaPss("SHA256"),
            HsmSignatureAlgorithm.rsaPss("SHA384"),
            HsmSignatureAlgorithm.rsaPss("SHA512"),
            HsmSignatureAlgorithm.pkcs1("SHA256withECDSA"),
            HsmSignatureAlgorithm.pkcs1("SHA384withECDSA"),
            HsmSignatureAlgorithm.pkcs1("SHA512withECDSA"),
    };

    /** HSM-only classical TLS sign; BC verify if JSSE ever routes verify to the alternate. */
    private static final class HsmSignatureSpi extends SignatureSpi {
        private final HsmSignatureAlgorithm algorithm;
        private final CryptoServerProvider cryptoServer;
        private Signature delegate;
        private AlgorithmParameterSpec pendingParams;
        private int messageBytes;

        HsmSignatureSpi(HsmSignatureAlgorithm algorithm, CryptoServerProvider cryptoServer) {
            this.algorithm = algorithm;
            this.cryptoServer = cryptoServer;
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            messageBytes = 0;
            try {
                delegate = Signature.getInstance(algorithm.cryptoServerName(), BouncyCastleProvider.PROVIDER_NAME);
                applyPendingParams();
                delegate.initVerify(publicKey);
            } catch (Exception e) {
                throw new InvalidKeyException("verify init failed", e);
            }
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            messageBytes = 0;
            try {
                delegate = Signature.getInstance(algorithm.cryptoServerName(), cryptoServer);
                applyPendingParams();
                delegate.initSign(privateKey);
            } catch (Exception e) {
                throw new InvalidKeyException(
                        "HSM sign init failed for " + algorithm.cryptoServerName()
                                + " — TLS identity must be an HSM key that supports this algorithm",
                        e
                );
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
                byte[] signature = HsmGate.call(delegate::sign);
                SigningAudit.log("CryptoServer", algorithm.cryptoServerName(), messageBytes);
                return signature;
            } catch (SignatureException e) {
                throw e;
            } catch (Exception e) {
                throw new SignatureException("HSM sign failed (" + algorithm.cryptoServerName() + ")", e);
            }
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            return delegate.verify(sigBytes);
        }

        @Override
        protected void engineSetParameter(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            pendingParams = params;
            if (delegate != null) {
                delegate.setParameter(params);
            }
        }

        @Override
        protected AlgorithmParameters engineGetParameters() {
            return delegate != null ? delegate.getParameters() : null;
        }

        private void applyPendingParams() throws InvalidAlgorithmParameterException {
            if (pendingParams != null) {
                delegate.setParameter(pendingParams);
            }
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

        static void log(String backend, String algorithm, int messageBytes) {
            System.out.println("[TLS] Identity signing on HSM ("
                    + backend + ", " + algorithm + "), message=" + messageBytes + " bytes");
        }
    }
}
