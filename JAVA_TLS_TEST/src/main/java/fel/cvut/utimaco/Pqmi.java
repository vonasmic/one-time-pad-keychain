package fel.cvut.utimaco;

import CryptoServerCXI.CryptoServerCXI;
import com.utimaco.cs2.mdl.any.CxiKeyAttributes;
import com.utimaco.cs2.mdl.pqmi.MLDSA_KeyGen;
import com.utimaco.cs2.mdl.pqmi.MLDSA_Sign;
import com.utimaco.cs2.mdl.pqmi.PqmiKeyStore;
import fel.cvut.tls.NodeTls;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** HSM PQMI client: env-based config, ephemeral CXI per operation, ML-DSA keygen/sign. */
public final class Pqmi implements AutoCloseable {

    public record KeyRef(String name, String group, int spec) {
        public KeyRef {
            if (name.isBlank() || group.isBlank()) {
                throw new IllegalArgumentException("name and group required");
            }
        }
    }

    @FunctionalInterface
    private interface SessionAction<T> {
        T run(CryptoServerCXI cxi, int pqmiMid) throws Exception;
    }

    private static final int ML_DSA_44 =
            com.utimaco.cs2.mdl.pqmi.Pqmi.ML_DSA_KT_FLAG | com.utimaco.cs2.mdl.pqmi.Pqmi.ML_DSA_KT_44;
    private static final int ADM_MID = 0x087;
    private static final int ADM_LIST_MODULES = 5;

    private final String device;
    private final int timeoutMs;
    private final String user;
    private final char[] pin;
    private final String group;
    private final int spec;
    private KeyRef identityKeyRef;
    private boolean closed;

    private Pqmi(
            String device,
            int timeoutMs,
            String user,
            char[] pin,
            String group,
            int spec
    ) {
        this.device = device;
        this.timeoutMs = timeoutMs;
        this.user = user;
        this.pin = pin;
        this.group = group;
        this.spec = spec;
    }

    /** Reads HSM env vars. Does not keep a persistent CXI session open. */
    public static Pqmi fromEnvironment() {
        String device = requireEnv("HSM_DEVICE");
        int timeoutMs = Integer.parseInt(requireEnv("HSM_TIMEOUT_MS"));
        String user = requireEnv("HSM_USER");
        char[] pin = requireEnv("HSM_PIN").toCharArray();
        String group = requireEnv("HSM_MLDSA_GROUP");
        int spec = Integer.parseInt(requireEnv("HSM_MLDSA_SPEC"));
        return new Pqmi(device, timeoutMs, user, pin, group, spec);
    }

    public KeyRef keyRefForNode(String nodeId) {
        return new KeyRef(NodeTls.certNameForNode(nodeId), group, spec);
    }

    /**
     * Loads an existing HSM identity key for runtime TLS signing.
     *
     * @throws IllegalStateException if the key is not present — provision via CertGenerator first
     */
    public void loadIdentityKey(KeyRef ref) throws Exception {
        withSession((cxi, mid) -> {
            byte[] handle = requireSigningHandle(mid, cxi, ref);
            Arrays.fill(handle, (byte) 0);
            identityKeyRef = ref;
            return null;
        });
    }

    /** Returns whether an identity key exists in the HSM store. */
    public boolean identityKeyExists(KeyRef ref) throws Exception {
        return withSession((cxi, mid) -> signingKeyExists(mid, cxi, ref));
    }

    /** Generates an identity key in the HSM. {@code overwrite=true} replaces an existing key. */
    public void generateIdentityKey(KeyRef ref, boolean overwrite) throws Exception {
        withSession((cxi, mid) -> {
            generateKey(mid, cxi, ref, overwrite);
            return null;
        });
    }

    public byte[] exportPublicKey(KeyRef ref) throws Exception {
        return withSession((cxi, mid) -> {
            PqmiKeyStore store = new PqmiKeyStore(
                    com.utimaco.cs2.mdl.pqmi.Pqmi.KEY_GET_PUBLIC_KEY, ML_DSA_44, attributes(ref));
            if (!store.exec(cxi, mid, com.utimaco.cs2.mdl.pqmi.Pqmi.SFC_KEYSTORE)) {
                throw new IllegalStateException("PQMI public-key export failed");
            }
            return extractRawPk(store.resp);
        });
    }

    public byte[] sign(byte[] message) throws Exception {
        if (message.length > 250 * 1024) {
            throw new IllegalArgumentException("message too large for PQMI eval");
        }
        KeyRef ref = identityKeyRef;
        if (ref == null) {
            throw new IllegalStateException("signing handle not loaded");
        }
        return withSession((cxi, mid) -> {
            byte[] handle = loadSigningHandle(mid, cxi, ref);
            try {
                return signOnce(cxi, mid, handle, message);
            } finally {
                Arrays.fill(handle, (byte) 0);
            }
        });
    }

    private <T> T withSession(SessionAction<T> action) throws Exception {
        return HsmGate.call(() -> {
            synchronized (this) {
                if (closed) {
                    throw new IllegalStateException("PQMI session is closed");
                }
                CryptoServerCXI cxi = null;
                try {
                    cxi = openSession();
                    int mid = resolvePqmiMid(cxi);
                    return action.run(cxi, mid);
                } finally {
                    closeQuietly(cxi);
                }
            }
        });
    }

    private CryptoServerCXI openSession() throws Exception {
        byte[] pinBytes = toBytes(pin);
        try {
            CryptoServerCXI cxi = new CryptoServerCXI(device, 3000);
            cxi.setTimeout(timeoutMs);
            logon(cxi, user, pinBytes);
            return cxi;
        } finally {
            Arrays.fill(pinBytes, (byte) 0);
        }
    }

    private static byte[] signOnce(CryptoServerCXI cxi, int pqmiMid, byte[] signingHandle, byte[] message)
            throws Exception {
        MLDSA_Sign sign = new MLDSA_Sign();
        sign.key(signingHandle);
        sign.type(ML_DSA_44);
        sign.flags(com.utimaco.cs2.mdl.pqmi.Pqmi.DILITHIUM_MODE_SIG_RAW
                | com.utimaco.cs2.mdl.pqmi.Pqmi.MODE_PSEUDO_RND);
        sign.msg(message);
        if (!sign.exec(cxi, pqmiMid, com.utimaco.cs2.mdl.pqmi.Pqmi.SFC_DILITHIUM_SIGN)) {
            throw new IllegalStateException("PQMI ML-DSA sign serialization failed");
        }
        return Arrays.copyOf(sign.resp, sign.resp.length);
    }

    public String device() {
        return device;
    }

    public int timeoutMs() {
        return timeoutMs;
    }

    public String user() {
        return user;
    }

    public char[] pin() {
        return pin;
    }

    public String group() {
        return group;
    }

    public int spec() {
        return spec;
    }

    public void zeroPin() {
        Arrays.fill(pin, '\0');
    }

    @Override
    public void close() {
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
            identityKeyRef = null;
            zeroPin();
        }
    }

    private void generateKey(int pqmiMid, CryptoServerCXI cxi, KeyRef ref, boolean overwrite) throws Exception {
        MLDSA_KeyGen gen = new MLDSA_KeyGen(cxi);
        gen.flags(com.utimaco.cs2.mdl.pqmi.Pqmi.MODE_PSEUDO_RND
                | (overwrite ? com.utimaco.cs2.mdl.pqmi.Pqmi.KEY_OVERWRITE : 0));
        gen.type(ML_DSA_44);
        gen.attributes(attributes(ref));
        gen.seed(new byte[0]);
        if (!gen.exec(cxi, pqmiMid, com.utimaco.cs2.mdl.pqmi.Pqmi.SFC_DILITHIUM_KEYGEN)) {
            throw new IllegalStateException("PQMI ML-DSA keygen serialization failed");
        }
    }

    private static byte[] loadSigningHandle(int pqmiMid, CryptoServerCXI cxi, KeyRef ref) throws Exception {
        PqmiKeyStore store = new PqmiKeyStore(
                com.utimaco.cs2.mdl.pqmi.Pqmi.KEY_LOAD_FROM_STORE, ML_DSA_44, attributes(ref));
        if (!store.exec(cxi, pqmiMid, com.utimaco.cs2.mdl.pqmi.Pqmi.SFC_KEYSTORE)) {
            throw new IllegalStateException("PQMI key load failed");
        }
        return Arrays.copyOf(store.resp, store.resp.length);
    }

    private static byte[] requireSigningHandle(int pqmiMid, CryptoServerCXI cxi, KeyRef ref) throws Exception {
        try {
            return loadSigningHandle(pqmiMid, cxi, ref);
        } catch (IllegalStateException e) {
            throw new IllegalStateException(
                    "HSM identity key not found: " + ref.group() + "/" + ref.name()
                            + " — run CertGenerator (option 3) after HSM init/reinit.",
                    e);
        }
    }

    private static boolean signingKeyExists(int pqmiMid, CryptoServerCXI cxi, KeyRef ref) {
        try {
            byte[] handle = loadSigningHandle(pqmiMid, cxi, ref);
            Arrays.fill(handle, (byte) 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static CxiKeyAttributes attributes(KeyRef ref) {
        CxiKeyAttributes a = new CxiKeyAttributes();
        a.name(ref.name().getBytes(StandardCharsets.US_ASCII));
        a.group(ref.group().getBytes(StandardCharsets.US_ASCII));
        a.spec(ref.spec());
        a.algo(CryptoServerCXI.KEY_ALGO_RAW);
        a.usage(CryptoServerCXI.KEY_USAGE_SIGN | CryptoServerCXI.KEY_USAGE_VERIFY);
        a.export(0);
        return a;
    }

    static byte[] extractRawPk(byte[] blob) {
        for (int i = 0; i + 6 <= blob.length; i++) {
            if (blob[i] == 'P' && blob[i + 1] == 'K') {
                int len = ByteBuffer.wrap(blob, i + 2, 4).getInt();
                byte[] raw = new byte[len];
                System.arraycopy(blob, i + 6, raw, 0, len);
                return raw;
            }
        }
        throw new IllegalStateException("PQMI public-key blob missing PK marker");
    }

    private static void logon(CryptoServerCXI cxi, String user, byte[] pinBytes) throws Exception {
        try {
            Method m = cxi.getClass().getMethod("logon", String.class, String.class, byte[].class);
            m.invoke(cxi, user, "", pinBytes);
            return;
        } catch (NoSuchMethodException ignored) {
        }
        cxi.logonPassword(user, pinBytes);
    }

    private static int resolvePqmiMid(CryptoServerCXI cxi) throws Exception {
        byte[] resp = cxi.exec(ADM_MID, ADM_LIST_MODULES, new byte[0]);
        ByteBuffer bb = ByteBuffer.wrap(resp);
        if (bb.remaining() < 2) {
            throw new IllegalStateException("ADM module list response too short");
        }
        short objLen = bb.getShort();
        while (bb.remaining() >= objLen && objLen > 0) {
            byte[] chunk = new byte[objLen];
            bb.get(chunk);
            ByteBuffer mod = ByteBuffer.wrap(chunk);
            short mid = mod.getShort();
            byte[] name = new byte[4];
            mod.get(name);
            if ("PQMI".equalsIgnoreCase(new String(name, StandardCharsets.US_ASCII))) {
                return mid & 0xFFFF;
            }
        }
        throw new IllegalStateException("PQMI module not found in HSM module list");
    }

    private static String requireEnv(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException("Required environment variable not set: " + name);
        }
        return v.trim();
    }

    private static byte[] toBytes(char[] pin) {
        byte[] out = new byte[pin.length];
        for (int i = 0; i < pin.length; i++) {
            out[i] = (byte) pin[i];
        }
        return out;
    }

    private static void closeQuietly(CryptoServerCXI cxi) {
        if (cxi != null) {
            try {
                cxi.close();
            } catch (Exception ignored) {
            }
        }
    }
}
