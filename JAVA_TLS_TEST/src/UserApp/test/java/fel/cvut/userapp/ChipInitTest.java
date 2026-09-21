package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeConstants;
import fel.cvut.se.SeManage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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
    void labRejectsAllZeroClientCsr() throws Exception {
        FakeChip chip = new FakeChip();
        chip.csrPub = new byte[SeConstants.MLDSA_PUB_LEN];
        ChipInit.EnrollResult r = ChipInit.enroll(chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest(null));
        assertFalse(r.ok());
        assertTrue(r.message().contains("all zeros"));
    }

    @Test
    void labFreshOwnerKeygenKemSignCreds() throws Exception {
        FakeChip chip = new FakeChip();
        FakeCerts certs = new FakeCerts();
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, certs, ChipInit.Profile.LAB, labRequest(null));
        assertTrue(r.ok());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT, SeManage.CMD_CREDS_DEVICE),
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
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest(null));
        assertTrue(r.ok());
        assertEquals(List.of(SeManage.CMD_KEM_INIT, SeManage.CMD_CREDS_DEVICE), chip.manageCmds);
    }

    @Test
    void alreadyEnrolledContinues() throws Exception {
        FakeChip chip = new FakeChip();
        chip.owner = new ChipInit.OwnerSetResult.AlreadyEnrolled();
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest(null));
        assertTrue(r.ok());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT, SeManage.CMD_CREDS_DEVICE),
                chip.manageCmds);
    }

    @Test
    void prodMissingCertWarnsAndSkipsPairing() throws Exception {
        FakeChip chip = new FakeChip();
        FakeCerts certs = new FakeCerts();
        certs.existingDevice = null;
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, certs, ChipInit.Profile.PROD, prodRequest("n", null));
        assertTrue(r.ok());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT), chip.manageCmds);
        assertNull(certs.lastPem);
    }

    @Test
    void prodPairsAfterInstallingExistingCert() throws Exception {
        FakeChip chip = new FakeChip();
        FakeCerts certs = new FakeCerts();
        certs.existingDevice = CERT;
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, certs, ChipInit.Profile.PROD, prodRequest("2", null));
        assertTrue(r.ok());
        assertEquals(List.of(
                SeManage.CMD_KEYGEN,
                SeManage.CMD_KEM_INIT,
                SeManage.CMD_CREDS_DEVICE,
                SeManage.CMD_PAIRING), chip.manageCmds);
    }

    @Test
    void prodOccupiedEccUsesCurrentPin() throws Exception {
        FakeChip chip = new FakeChip();
        chip.eccPub = ECC;
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.PROD, prodRequest("n", "oldpin12"));
        assertTrue(r.ok());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT, SeManage.CMD_CREDS_DEVICE),
                chip.manageCmds);
        assertEquals("oldpin12", chip.lastKeygenPin);
    }

    @Test
    void prodOccupiedWithoutCurrentPinStops() throws Exception {
        FakeChip chip = new FakeChip();
        chip.eccPub = ECC;
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.PROD, prodRequest("n", null));
        assertFalse(r.ok());
        assertEquals("KEYGEN", r.stoppedAt());
        assertTrue(chip.manageCmds.isEmpty());
    }

    @Test
    void keygenFailureStops() throws Exception {
        FakeChip chip = new FakeChip();
        chip.keygen = new SeManage.Reply(SeManage.ERR, "KEYGEN failed");
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest(null));
        assertFalse(r.ok());
        assertEquals("KEYGEN", r.stoppedAt());
        assertEquals(List.of(SeManage.CMD_KEYGEN), chip.manageCmds);
    }

    @Test
    void kemFailureStops() throws Exception {
        FakeChip chip = new FakeChip();
        chip.kem = new SeManage.Reply(SeManage.SLOT_OCC, "occupied");
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest(null));
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
                chip, new FakeCerts(), ChipInit.Profile.PROD, prodRequest("n", "oldpin12"));
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
        chip.creds = new SeManage.Reply(SeManage.ERR, "CREDS DEVICE failed");
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest(null));
        assertFalse(r.ok());
        assertEquals("CREDS DEVICE", r.stoppedAt());
        assertEquals(List.of(SeManage.CMD_KEYGEN, SeManage.CMD_KEM_INIT, SeManage.CMD_CREDS_DEVICE),
                chip.manageCmds);
    }

    @Test
    void ownerSetFailureStops() throws Exception {
        FakeChip chip = new FakeChip();
        chip.owner = new ChipInit.OwnerSetResult.Failed("auth: bad frame");
        ChipInit.EnrollResult r = ChipInit.enroll(
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest(null));
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
                chip, new FakeCerts(), ChipInit.Profile.LAB, labRequest(null));
        assertTrue(r.ok());
        assertEquals(1, chip.clientHashReads);
        assertTrue(r.message().contains("CLIENT HASH unavailable"));
    }

    private static ChipInit.EnrollRequest labRequest(String currentPin) {
        return new ChipInit.EnrollRequest(
                PW, "12345678", currentPin, Optional.empty(),
                Path.of("client", "client-cert.pem"),
                Path.of("ca", "client_ca.p12"),
                "device", SPKI, SAE_CA);
    }

    private static ChipInit.EnrollRequest prodRequest(String slot, String currentPin) {
        Optional<Integer> pairing = "n".equalsIgnoreCase(slot) ? Optional.empty() : Optional.of(Integer.parseInt(slot));
        return new ChipInit.EnrollRequest(
                PW, "12345678", currentPin, pairing,
                Path.of("client", "client-cert.pem"),
                Path.of("ca", "client_ca.p12"),
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
        SeManage.Reply creds = new SeManage.Reply(SeManage.OK, "CREDS DEVICE ok");
        SeManage.Reply pairing = new SeManage.Reply(SeManage.OK, "PAIRING ok");

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
            if (cmd == SeManage.CMD_CREDS_DEVICE) {
                return creds;
            }
            if (cmd == SeManage.CMD_PAIRING) {
                return pairing;
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

        @Override
        public byte[] signLab(Path clientCaP12, byte[] csrPub, String deviceCn) {
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
        public boolean isRegularFile(Path path) {
            return caExists && path != null;
        }
    }
}
