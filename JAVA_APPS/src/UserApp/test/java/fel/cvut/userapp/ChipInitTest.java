package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeManage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChipInitTest {

    private static final byte[] PW = "password".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SPKI = filled(SeConstants.MLDSA_PUB_LEN, (byte) 0x11);
    private static final byte[] SAE_CA = {0x30, 0x00};
    private static final byte[] CSR = filled(SeConstants.MLDSA_PUB_LEN, (byte) 0x22);
    private static final byte[] ECC = filled(SeConstants.ECC_PUB_LEN, (byte) 0x33);
    private static final byte[] CERT = {0x30, 0x03, 0x02, 0x01, 0x00};
    private static final byte[] PAIRING_PRIV = filled(SeConstants.PAIRING_KEY_LEN, (byte) 0xAB);
    private static final byte[] PAIRING_PUB = filled(SeConstants.PAIRING_KEY_LEN, (byte) 0xCD);

    @Test
    void ownerPasswordRequiresMatchingConfirmation() {
        assertEquals("strongpw1", ChipInit.readOwnerPassword(new Scanner("strongpw1\nstrongpw1\n")));
        assertNull(ChipInit.readOwnerPassword(new Scanner("strongpw1\nstrongpw2\n")));
        assertNull(ChipInit.readOwnerPassword(new Scanner("short\n")));
    }

    @Test
    void pairingChoiceAcceptsSlotsOrSkip() {
        assertEquals(Optional.of(1), ChipInit.parsePairingChoice("1"));
        assertEquals(Optional.of(3), ChipInit.parsePairingChoice(" 3 "));
        assertEquals(Optional.empty(), ChipInit.parsePairingChoice("n"));
        assertEquals(Optional.empty(), ChipInit.parsePairingChoice("N"));
        assertNull(ChipInit.parsePairingChoice("0"));
        assertNull(ChipInit.parsePairingChoice("yes"));
        assertNull(ChipInit.parsePairingChoice(""));
        assertNull(ChipInit.parsePairingChoice(null));
    }

    @Test
    void initLabAndProdCommandsAreRecognized() {
        assertTrue(ChipInit.isInitLab("INIT LAB"));
        assertTrue(ChipInit.isInitLab("init lab"));
        assertTrue(ChipInit.isInitLab("INITLAB"));
        assertTrue(ChipInit.isInitLab("  init   lab  "));
        assertFalse(ChipInit.isInitLab("INIT"));
        assertFalse(ChipInit.isInitLab("INIT PROD"));
        assertFalse(ChipInit.isInitLab(null));

        assertTrue(ChipInit.isInitProd("INIT PROD"));
        assertTrue(ChipInit.isInitProd("init prod"));
        assertTrue(ChipInit.isInitProd("INITPROD"));
        assertFalse(ChipInit.isInitProd("INIT LAB"));
        assertFalse(ChipInit.isInitProd("INIT"));
        assertFalse(ChipInit.isInitProd(null));
    }

    @Test
    void csrFileRoundTrip(@TempDir Path dir) throws Exception {
        byte[] pub = new byte[SeConstants.MLDSA_PUB_LEN];
        pub[0] = 0x11;
        pub[pub.length - 1] = 0x22;
        Path file = dir.resolve("client").resolve("client-csr.hex");
        ChipInit.writeCsrHex(file, pub);
        assertTrue(Files.isRegularFile(file));
        String hex = Files.readString(file).strip();
        assertEquals(SeBytes.toHex(pub), hex);
    }

    @Test
    void pairingKeyFileRoundTrip(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("client").resolve("pairing-key.hex");
        ChipInit.writePairingKeyHex(file, 2, PAIRING_PRIV, PAIRING_PUB);
        assertTrue(Files.isRegularFile(file));
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(file));
        SeManage.PairingKey key = ChipInit.readPairingKeyHex(file);
        assertEquals(2, key.slot());
        assertArrayEquals(PAIRING_PRIV, key.priv());
        assertArrayEquals(PAIRING_PUB, key.pub());
        assertEquals(file, ChipInit.pairingKeyPath(dir.resolve("client").resolve("client-cert.pem")));
    }

    @Test
    void labRejectsAllZeroClientCsr() throws Exception {
        FakeChip chip = new FakeChip();
        chip.csrPub = new byte[SeConstants.MLDSA_PUB_LEN];
        ChipInit.EnrollResult r = ChipInit.enroll(chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest());
        assertFalse(r.ok());
        assertTrue(r.message().contains("all zeros"));
    }

    @Test
    void labFreshOwnerKeygenKemSignCreds() throws Exception {
        FakeChip chip = new FakeChip();
        FakeCerts certs = new FakeCerts();
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, certs, ChipInit.Profile.LAB, labRequest());
        assertTrue(r.ok());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT, SeManage.CMD_INSERT_SIGNED_CSR),
                chip.manageCmds);
        assertArrayEquals(CSR, certs.lastCsr);
        assertArrayEquals(CERT, certs.lastPem);
        assertEquals(1, chip.ownerSets);
        assertEquals(1, chip.clientHashReads);
        assertTrue(r.message().contains("CLIENT HASH (96 hex):"));
        assertTrue(r.message().contains(SeBytes.toHex(chip.clientHash)));
    }

    @Test
    void labSkipsOccupiedEcc() throws Exception {
        FakeChip chip = new FakeChip();
        chip.eccPub = ECC;
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest());
        assertTrue(r.ok());
        assertEquals(List.of(SeManage.CMD_KEM_INIT, SeManage.CMD_INSERT_SIGNED_CSR), chip.manageCmds);
    }

    @Test
    void alreadyEnrolledContinues() throws Exception {
        FakeChip chip = new FakeChip();
        chip.owner = new ChipInit.OwnerSetResult.AlreadyEnrolled();
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest());
        assertTrue(r.ok());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT, SeManage.CMD_INSERT_SIGNED_CSR),
                chip.manageCmds);
    }

    @Test
    void prodMissingCertWarnsAndSkipsPairing() throws Exception {
        FakeChip chip = new FakeChip();
        FakeCerts certs = new FakeCerts();
        certs.existingDevice = null;
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, certs, ChipInit.Profile.PROD, prodRequest("n"));
        assertTrue(r.ok());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT), chip.manageCmds);
        assertNull(certs.lastPem);
    }

    @Test
    void prodDoesNotInstallExistingCert() throws Exception {
        FakeChip chip = new FakeChip();
        FakeCerts certs = new FakeCerts();
        certs.existingDevice = CERT;
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, certs, ChipInit.Profile.PROD, prodRequest("2"));
        assertTrue(r.ok());
        assertEquals(List.of(
                SeManage.CMD_KEYGEN,
                SeManage.CMD_KEM_INIT,
                SeManage.CMD_PAIRING), chip.manageCmds);
        assertNull(certs.lastPem);
        assertEquals(2, certs.lastPairingSlot);
        assertArrayEquals(PAIRING_PRIV, certs.lastPairingPriv);
        assertArrayEquals(PAIRING_PUB, certs.lastPairingPub);
        assertEquals(Path.of("client", "pairing-key.hex"), certs.lastPairingPath);
        assertFalse(r.message().contains(SeBytes.toHex(PAIRING_PRIV)));
        assertTrue(r.message().contains("pairing-key.hex"));
    }

    @Test
    void prodBarePairingOkStopsWithoutSaving() throws Exception {
        FakeChip chip = new FakeChip();
        chip.pairing = new SeManage.Reply(SeManage.OK, "PAIRING ok");
        FakeCerts certs = new FakeCerts();
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, certs, ChipInit.Profile.PROD, prodRequest("2"));
        assertFalse(r.ok());
        assertEquals("PAIRING", r.stoppedAt());
        assertTrue(r.message().contains("was not in the reply"));
        assertNull(certs.lastPairingPriv);
        assertFalse(r.message().contains(SeBytes.toHex(PAIRING_PRIV)));
    }

    @Test
    void prodOccupiedEccReplacesWithoutPin() throws Exception {
        FakeChip chip = new FakeChip();
        chip.eccPub = ECC;
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.PROD, prodRequest("n"));
        assertTrue(r.ok());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT),
                chip.manageCmds);
        assertNull(chip.lastKeygenPin);
    }

    @Test
    void keygenFailureStops() throws Exception {
        FakeChip chip = new FakeChip();
        chip.keygen = new SeManage.Reply(SeManage.ERR, "KEYGEN failed");
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest());
        assertFalse(r.ok());
        assertEquals("KEYGEN", r.stoppedAt());
        assertEquals(List.of(SeManage.CMD_KEYGEN), chip.manageCmds);
    }

    @Test
    void kemFailureStops() throws Exception {
        FakeChip chip = new FakeChip();
        chip.kem = new SeManage.Reply(SeManage.SLOT_OCC, "occupied");
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest());
        assertFalse(r.ok());
        assertEquals("KEM INIT", r.stoppedAt());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT), chip.manageCmds);
    }

    @Test
    void kemAlreadyProvisionedRefusesBeforeManage() throws Exception {
        FakeChip chip = new FakeChip();
        chip.kemPub = filled(SeConstants.MLKEM_PK_LEN, (byte) 0x44);
        chip.eccPub = ECC;
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.PROD, prodRequest("n"));
        assertFalse(r.ok());
        assertEquals("INIT", r.stoppedAt());
        assertEquals(ChipInit.MSG_KEM_ALREADY_PROVISIONED, r.message());
        assertTrue(chip.manageCmds.isEmpty());
        assertEquals(0, chip.ownerSets);
        assertEquals(0, chip.clientHashReads);
    }

    @Test
    void credsFailureStops() throws Exception {
        FakeChip chip = new FakeChip();
        chip.creds = new SeManage.Reply(SeManage.ERR, "INSERT SIGNED CSR failed");
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest());
        assertFalse(r.ok());
        assertEquals("INSERT SIGNED CSR", r.stoppedAt());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT, SeManage.CMD_INSERT_SIGNED_CSR),
                chip.manageCmds);
    }

    @Test
    void ownerSetFailureStops() throws Exception {
        FakeChip chip = new FakeChip();
        chip.owner = new ChipInit.OwnerSetResult.Failed("auth: bad frame");
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest());
        assertFalse(r.ok());
        assertEquals("OWNER SET", r.stoppedAt());
        assertTrue(chip.manageCmds.isEmpty());
        assertEquals(0, chip.clientHashReads);
    }

    @Test
    void missingClientHashDoesNotFailInit() throws Exception {
        FakeChip chip = new FakeChip();
        chip.clientHash = null;
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest());
        assertTrue(r.ok());
        assertEquals(1, chip.clientHashReads);
        assertTrue(r.message().contains("CLIENT HASH unavailable"));
    }

    private static ChipInit.EnrollRequest labRequest() {
        return new ChipInit.EnrollRequest(
                PW, "12345678", Optional.empty(),
                Path.of("client", "client-cert.pem"),
                Path.of("ca", "client_ca.p12"),
                "password",
                "device", SPKI, SAE_CA);
    }

    private static ChipInit.EnrollRequest prodRequest(String slot) {
        Optional<Integer> pairing = "n".equalsIgnoreCase(slot) ? Optional.empty() : Optional.of(Integer.parseInt(slot));
        return new ChipInit.EnrollRequest(
                PW, "12345678", pairing,
                Path.of("client", "client-cert.pem"),
                Path.of("ca", "client_ca.p12"),
                null,
                "device", SPKI, SAE_CA);
    }

    private static byte[] filled(int n, byte v) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = v;
        }
        return b;
    }

    private static final class FakeChip implements ChipInit.ChipPort {
        ChipInit.OwnerSetResult owner = new ChipInit.OwnerSetResult.Ok();
        byte[] eccPub;
        byte[] kemPub;
        byte[] csrPub = CSR;
        byte[] clientHash = filled(SeConstants.CLIENT_HASH_LEN, (byte) 0x55);
        final List<Integer> manageCmds = new ArrayList<>();
        String lastKeygenPin;
        int ownerSets;
        int clientHashReads;
        SeManage.Reply keygen = new SeManage.Reply(SeManage.OK, "KEYGEN ok");
        SeManage.Reply kem = new SeManage.Reply(SeManage.OK, "KEM INIT ok");
        SeManage.Reply creds = new SeManage.Reply(SeManage.OK, "INSERT SIGNED CSR ok");
        SeManage.Reply pairing;

        @Override
        public ChipInit.OwnerSetResult ownerSet(byte[] password, byte[] spki, byte[] saeCa) {
            ownerSets++;
            return owner;
        }

        @Override
        public Optional<byte[]> tropicPub() {
            return Optional.ofNullable(eccPub);
        }

        @Override
        public Optional<byte[]> tropicKemPub() {
            return Optional.ofNullable(kemPub);
        }

        @Override
        public SeManage.Reply manage(int cmd, String pin, byte[] body) {
            manageCmds.add(cmd);
            if (cmd == SeManage.CMD_KEYGEN) {
                lastKeygenPin = pin;
                return keygen;
            }
            if (cmd == SeManage.CMD_KEM_INIT) {
                return kem;
            }
            if (cmd == SeManage.CMD_INSERT_SIGNED_CSR) {
                return creds;
            }
            if (cmd == SeManage.CMD_PAIRING) {
                if (pairing != null) {
                    return pairing;
                }
                int slot = (body != null && body.length == 1) ? (body[0] & 0xFF) : 1;
                return new SeManage.Reply(SeManage.OK,
                        SeManage.formatPairingOkMsg(new SeManage.PairingKey(slot, PAIRING_PRIV, PAIRING_PUB)));
            }
            return new SeManage.Reply(SeManage.BAD_CMD, "bad command");
        }

        @Override
        public byte[] clientCsrPub() {
            return csrPub;
        }

        @Override
        public Optional<byte[]> clientHash() {
            clientHashReads++;
            return Optional.ofNullable(clientHash);
        }
    }

    private static final class FakeCerts implements ChipInit.Certs {
        boolean caExists = true;
        byte[] existingDevice = CERT;
        byte[] lastCsr;
        byte[] lastPem;
        Path lastPairingPath;
        Integer lastPairingSlot;
        byte[] lastPairingPriv;
        byte[] lastPairingPub;

        @Override
        public byte[] signLab(Path clientCaP12, String clientCaP12Password, byte[] csrPub, String deviceCn) {
            return CERT;
        }

        @Override
        public void writePem(byte[] certDer, Path path) {
            lastPem = certDer;
        }

        @Override
        public Optional<byte[]> loadDerIfPresent(Path path) {
            return Optional.ofNullable(existingDevice);
        }

        @Override
        public void writeCsrHex(Path path, byte[] pub) {
            lastCsr = pub;
        }

        @Override
        public void writePairingKeyHex(Path path, int slot, byte[] priv, byte[] pub) {
            lastPairingPath = path;
            lastPairingSlot = slot;
            lastPairingPriv = priv;
            lastPairingPub = pub;
        }

        @Override
        public boolean isRegularFile(Path path) {
            return caExists && path != null;
        }
    }
}
