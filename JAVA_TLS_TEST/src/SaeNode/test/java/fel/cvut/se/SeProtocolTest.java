package fel.cvut.se;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SeProtocolTest {

    @BeforeAll
    static void addBc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void lvRoundTripPreservesVersionAndItems() throws Exception {
        List<byte[]> items = List.of(
                new byte[] {1, 2, 3},
                new byte[0],
                new byte[1088]
        );
        byte[] encoded = SecureLv.encode(SeConstants.LV_DOWNLINK_VERSION, items);
        SecureLv.Envelope decoded = SecureLv.decode(encoded);
        assertEquals(SeConstants.LV_DOWNLINK_VERSION, decoded.version());
        assertEquals(3, decoded.items().size());
        assertArrayEquals(items.get(0), decoded.items().get(0));
        assertEquals(0, decoded.items().get(1).length);
        assertEquals(1088, decoded.items().get(2).length);
    }

    @Test
    void lvRejectsWrongUplinkVersion() {
        byte[] encoded = SecureLv.encode(1, List.of(new byte[64], new byte[64]));
        assertThrows(IOException.class, () ->
                SeSessionUplink.readAndVerify(
                        new ByteArrayInputStream(encoded),
                        new byte[32],
                        new byte[32]));
    }

    @Test
    void lvReadDoesNotRequireEof() throws Exception {
        byte[] envelope = SecureLv.encode(2, List.of(new byte[] {9}));
        byte[] withTrailing = new byte[envelope.length + 4];
        System.arraycopy(envelope, 0, withTrailing, 0, envelope.length);
        withTrailing[envelope.length] = 0x55;
        SecureLv.Envelope decoded = SecureLv.readFrom(new ByteArrayInputStream(withTrailing));
        assertEquals(2, decoded.version());
        assertEquals(1, decoded.items().size());
        assertArrayEquals(new byte[] {9}, decoded.items().get(0));
    }

    @Test
    void maxPadsRespects200KiBBudgetIncludingDecryptHalf() {
        SeSessionUplink uplink = new SeSessionUplink(
                new byte[SeConstants.CLIENT_HASH_LEN], 475, 507, new byte[SeConstants.FILL_ID_LEN],
                new byte[SeConstants.MLKEM_PK_LEN],
                List.of(new SeSessionUplink.PeerEntry(new byte[SeConstants.PEER_HASH_LEN], "Alice")));
        int n = uplink.maxPadsForBudget();
        assertTrue(n < 507);
        int framing = SeConstants.MLKEM_CT_LEN + SeConstants.DECRYPT_HALF_LEN;
        assertTrue(framing + n * 475 <= SeConstants.QKD_MAX_BYTES);
        assertTrue(framing + (n + 1) * 475 > SeConstants.QKD_MAX_BYTES);
    }

    @Test
    void sealedFillDownlinkIsV2WithKemCtDecryptHalfAndPadImages() throws Exception {
        SecureRandom random = new SecureRandom();
        MLKEMKeyPairGenerator kpg = new MLKEMKeyPairGenerator();
        kpg.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        byte[] pk = ((MLKEMPublicKeyParameters) kp.getPublic()).getEncoded();

        int slotSize = 64;
        int plainMax = slotSize - SeConstants.RMEM_OVERHEAD;
        int padCount = 3;
        byte[] fillId = new byte[32];
        random.nextBytes(fillId);

        SeSessionUplink uplink = buildVerifiedUplink(slotSize, padCount, fillId, pk, random);
        byte[] padBytes = new byte[plainMax * padCount];
        random.nextBytes(padBytes);
        List<String> b64 = List.of(Base64.getEncoder().encodeToString(padBytes));

        byte[] downlink = new SeKemFill(random).buildDownlink(
                uplink, b64, SeConstants.DECRYPT_HALF_ORIGIN);
        SecureLv.Envelope env = SecureLv.decode(downlink);
        assertEquals(SeConstants.LV_DOWNLINK_VERSION, env.version());
        assertEquals(2 + padCount, env.items().size());
        assertEquals(SeConstants.MLKEM_CT_LEN, env.items().get(0).length);
        assertArrayEquals(new byte[] {SeConstants.DECRYPT_HALF_ORIGIN}, env.items().get(1));
        for (int i = 0; i < padCount; i++) {
            assertEquals(slotSize, env.items().get(2 + i).length);
        }

        MLKEMExtractor extractor = new MLKEMExtractor((MLKEMPrivateKeyParameters) kp.getPrivate());
        byte[] ss = extractor.extractSecret(env.items().get(0));
        byte[] ss32 = Arrays.copyOf(ss, SeConstants.MLKEM_SS_LEN);
        byte[] key = SeKemFill.slotKey(ss32, fillId, 0);
        byte[] opened = aeadOpen(key, 0, env.items().get(2));
        assertArrayEquals(Arrays.copyOfRange(padBytes, 0, plainMax), opened);
    }

    @Test
    void sealedFillDownlinkEncodesPeerDecryptHalf() throws Exception {
        SecureRandom random = new SecureRandom();
        MLKEMKeyPairGenerator kpg = new MLKEMKeyPairGenerator();
        kpg.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        byte[] pk = ((MLKEMPublicKeyParameters) kp.getPublic()).getEncoded();
        int slotSize = 64;
        int plainMax = slotSize - SeConstants.RMEM_OVERHEAD;
        byte[] fillId = new byte[32];
        random.nextBytes(fillId);
        SeSessionUplink uplink = buildVerifiedUplink(slotSize, 1, fillId, pk, random);
        List<String> b64 = List.of(Base64.getEncoder().encodeToString(new byte[plainMax]));

        byte[] downlink = new SeKemFill(random).buildDownlink(
                uplink, b64, SeConstants.DECRYPT_HALF_PEER);
        SecureLv.Envelope env = SecureLv.decode(downlink);
        assertEquals(SeConstants.LV_DOWNLINK_VERSION, env.version());
        assertArrayEquals(new byte[] {SeConstants.DECRYPT_HALF_PEER}, env.items().get(1));
    }

    @Test
    void sealedFillRejectsInvalidDecryptHalf() {
        SeSessionUplink uplink = new SeSessionUplink(
                new byte[SeConstants.CLIENT_HASH_LEN], 64, 1, new byte[SeConstants.FILL_ID_LEN],
                new byte[SeConstants.MLKEM_PK_LEN],
                List.of(new SeSessionUplink.PeerEntry(new byte[SeConstants.PEER_HASH_LEN], "Alice")));
        assertThrows(IllegalArgumentException.class, () ->
                new SeKemFill().buildDownlink(uplink, List.of("YQ=="), (byte) 2));
    }

    @Test
    void partialFillPutsEqualPadsInEachHalf() throws Exception {
        SecureRandom random = new SecureRandom();
        MLKEMKeyPairGenerator kpg = new MLKEMKeyPairGenerator();
        kpg.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        byte[] pk = ((MLKEMPublicKeyParameters) kp.getPublic()).getEncoded();
        int slotSize = 64;
        int plainMax = slotSize - SeConstants.RMEM_OVERHEAD;
        byte[] fillId = new byte[32];
        random.nextBytes(fillId);
        SeSessionUplink uplink = buildVerifiedUplink(slotSize, 6, fillId, pk, random);
        List<String> b64 = List.of(Base64.getEncoder().encodeToString(new byte[plainMax * 4]));

        SecureLv.Envelope env = SecureLv.decode(new SeKemFill(random).buildDownlink(
                uplink, b64, SeConstants.DECRYPT_HALF_ORIGIN));
        assertEquals(7, env.items().size());
        assertEquals(slotSize, env.items().get(2).length);
        assertEquals(slotSize, env.items().get(3).length);
        assertEquals(0, env.items().get(4).length);
        assertEquals(slotSize, env.items().get(5).length);
        assertEquals(slotSize, env.items().get(6).length);
    }

    @Test
    void uplinkVerifyAcceptsValidSessionBinding() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] fillId = new byte[32];
        random.nextBytes(fillId);
        SeSessionUplink uplink = buildVerifiedUplink(475, 507, fillId, new byte[SeConstants.MLKEM_PK_LEN], random);
        assertEquals(475, uplink.slotSize());
        assertEquals(507, uplink.padCount());
        assertEquals(475 - SeConstants.RMEM_OVERHEAD, uplink.plainMax());
        assertEquals(SeConstants.MLKEM_PK_LEN, uplink.mlkemPublicKey().length);
        assertEquals(1, uplink.peers().size());
    }

    @Test
    void provisionAckParsesSeOkLine() throws Exception {
        SeProvisionAck.Result ack = SeProvisionAck.read(
                new ByteArrayInputStream("SE_OK 241913\n".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(241913L, ack.tropicBytes());
        assertEquals("Device consumed 236.2 KB", ack.downloadMessage());
    }

    @Test
    void provisionAckRejectsUnexpectedLine() {
        assertThrows(IOException.class, () -> SeProvisionAck.read(
                new ByteArrayInputStream("SE_ERR\n".getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    void uplinkRejectsVersion2AsSchemaMismatch() {
        byte[] encoded = SecureLv.encode(2, List.of(new byte[64], new byte[64]));
        IOException ex = assertThrows(IOException.class, () ->
                SeSessionUplink.readAndVerify(
                        new ByteArrayInputStream(encoded),
                        new byte[32],
                        new byte[32]));
        assertTrue(ex.getMessage().contains("expect v" + SeConstants.LV_UPLINK_VERSION));
    }

    private static SeSessionUplink buildVerifiedUplink(
            int slotSize, int padCount, byte[] fillId, byte[] mlkemPublicKey, SecureRandom random
    ) throws Exception {
        X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
        ECDomainParameters domain = new ECDomainParameters(
                curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(domain, random));
        AsymmetricCipherKeyPair ecc = gen.generateKeyPair();
        ECPublicKeyParameters pub = (ECPublicKeyParameters) ecc.getPublic();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters) ecc.getPrivate();

        byte[] xy = encodeXy(pub.getQ());
        byte[] peerSpki = new byte[64];
        random.nextBytes(peerSpki);
        byte[] exporter = new byte[32];
        random.nextBytes(exporter);

        byte[] clientHash = SeBytes.sha384(SeBytes.concat(peerSpki, xy));
        byte[] toSign = SeBytes.sha384(SeBytes.concat(clientHash, exporter));
        byte[] sig = signRaw(priv, toSign);

        List<byte[]> items = new ArrayList<>();
        items.add(sig);
        items.add(xy);
        items.add(clientHash);
        items.add(SeBytes.u16Le(slotSize));
        items.add(SeBytes.u16Le(padCount));
        items.add(fillId);
        items.add(mlkemPublicKey);
        items.add(new byte[SeConstants.PEER_HASH_LEN]);
        items.add("Alice".getBytes(StandardCharsets.UTF_8));

        byte[] wire = SecureLv.encode(SeConstants.LV_UPLINK_VERSION, items);
        return SeSessionUplink.readAndVerify(new ByteArrayInputStream(wire), exporter, peerSpki);
    }

    private static byte[] aeadOpen(byte[] key, int logical, byte[] image) throws Exception {
        assertEquals(SeConstants.RMEM_VER, image[0] & 0xFF);
        byte[] nonce = Arrays.copyOfRange(image, 1, 1 + SeConstants.RMEM_NONCE_LEN);
        byte[] ctAndTag = Arrays.copyOfRange(image, 1 + SeConstants.RMEM_NONCE_LEN, image.length);
        byte[] aad = SeBytes.u16Le(logical);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(SeConstants.RMEM_TAG_LEN * 8, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(ctAndTag);
    }

    private static byte[] encodeXy(ECPoint q) {
        byte[] encoded = q.getEncoded(false);
        return Arrays.copyOfRange(encoded, 1, 65);
    }

    private static byte[] signRaw(ECPrivateKeyParameters priv, byte[] digest) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, priv);
        BigInteger[] rs = signer.generateSignature(digest);
        byte[] out = new byte[64];
        toFixed(rs[0], out, 0);
        toFixed(rs[1], out, 32);
        return out;
    }

    private static void toFixed(BigInteger v, byte[] out, int off) {
        byte[] raw = v.toByteArray();
        Arrays.fill(out, off, off + 32, (byte) 0);
        int copy = Math.min(32, raw.length);
        System.arraycopy(raw, raw.length - copy, out, off + 32 - copy, copy);
    }
}
