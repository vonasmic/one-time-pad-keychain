package fel.cvut.userapp;

import fel.cvut.se.SeConstants;
import fel.cvut.se.SeManage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Tag("unit")
class ChipInitEdgeCasesTest {

    private static final byte[] PW = "password".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SPKI = filled(SeConstants.MLDSA_PUB_LEN, (byte) 0x11);
    private static final byte[] CSR = filled(SeConstants.MLDSA_PUB_LEN, (byte) 0x22);
    private static final SeManage.Reply OK = new SeManage.Reply(SeManage.OK, "ok");

    private ChipInit.ChipPort chip;
    private ChipInit.Certs certs;

    @BeforeEach
    void setUp() throws Exception {
        chip = mock(ChipInit.ChipPort.class);
        certs = mock(ChipInit.Certs.class);
        when(chip.tropicKemPub()).thenReturn(Optional.empty());
        when(chip.ownerSet(any(), any(), any())).thenReturn(new ChipInit.OwnerSetResult.Ok());
        when(chip.tropicPub()).thenReturn(Optional.empty());
        when(chip.manage(anyInt(), any(), any())).thenReturn(OK);
        when(chip.clientCsrPub()).thenReturn(CSR);
        when(chip.clientHash()).thenReturn(Optional.empty());
    }


    @Test
    void labStopsWhenClientCaPkcs12Missing() throws Exception {
        when(certs.isRegularFile(any())).thenReturn(false);
        ChipInit.EnrollResult r = ChipInit.enroll(chip, certs, ChipInit.Profile.LAB,
                request(Optional.empty(), Path.of("ca", "missing.p12"), "pw"));
        assertFalse(r.ok());
        assertEquals("INSERT SIGNED CSR", r.stoppedAt());
        assertTrue(r.message().contains("missing.p12"));
        verify(certs, never()).signLab(any(), any(), any(), any());

        ChipInit.EnrollResult noPath = ChipInit.enroll(chip, certs, ChipInit.Profile.LAB,
                request(Optional.empty(), null, "pw"));
        assertEquals("INSERT SIGNED CSR", noPath.stoppedAt());
    }

    @Test
    void labStopsWhenClientCaPasswordMissing() throws Exception {
        when(certs.isRegularFile(any())).thenReturn(true);
        for (String pw : new String[] {null, ""}) {
            ChipInit.EnrollResult r = ChipInit.enroll(chip, certs, ChipInit.Profile.LAB,
                    request(Optional.empty(), Path.of("ca.p12"), pw));
            assertEquals("INSERT SIGNED CSR", r.stoppedAt());
            assertTrue(r.message().contains("USERAPP_CLIENT_CA_P12_PASSWORD"));
        }
        verify(certs, never()).signLab(any(), any(), any(), any());
    }

    @Test
    void labInsertFailureIsReported() throws Exception {
        when(certs.isRegularFile(any())).thenReturn(true);
        byte[] der = {0x30, 0x00};
        when(certs.signLab(any(), anyString(), any(), anyString())).thenReturn(der);
        when(chip.manage(eq(SeManage.CMD_INSERT_SIGNED_CSR), isNull(), any()))
                .thenReturn(new SeManage.Reply(SeManage.BAD_CMD, "cert rejected"));
        ChipInit.EnrollResult r = ChipInit.enroll(chip, certs, ChipInit.Profile.LAB,
                request(Optional.empty(), Path.of("ca.p12"), "pw"));
        assertEquals("INSERT SIGNED CSR", r.stoppedAt());
        verify(certs).writePem(eq(der), eq(Path.of("client", "client-cert.pem")));
    }

    @Test
    void prodPairingFailureStops() throws Exception {
        when(chip.manage(eq(SeManage.CMD_PAIRING), isNull(), any()))
                .thenReturn(new SeManage.Reply(SeManage.BAD_CMD, "slot locked"));
        ChipInit.EnrollResult r = ChipInit.enroll(chip, certs, ChipInit.Profile.PROD,
                request(Optional.of(2), null, null));
        assertEquals("PAIRING", r.stoppedAt());
        verify(certs, never()).writePairingKeyHex(any(), anyInt(), any(), any());
    }

    @Test
    void finishedEnrollmentIncludesClientHashWhenAvailable() throws Exception {
        when(chip.clientHash()).thenReturn(Optional.of(new byte[] {(byte) 0xab, 0x01}));
        ChipInit.EnrollResult r = ChipInit.enroll(chip, certs, ChipInit.Profile.PROD,
                request(Optional.empty(), null, null));
        assertTrue(r.ok());
        assertTrue(r.message().endsWith("Client hash (96 hex):\nab01"), r.message());
    }

    @Test
    void exportClientCsrValidatesDevicePublicKey() throws Exception {
        when(chip.clientCsrPub()).thenReturn(null);
        assertThrows(IOException.class, () -> ChipInit.exportClientCsr(chip, certs, Path.of("c", "cert.pem")));
        when(chip.clientCsrPub()).thenReturn(new byte[10]);
        IOException truncated = assertThrows(IOException.class,
                () -> ChipInit.exportClientCsr(chip, certs, Path.of("c", "cert.pem")));
        assertTrue(truncated.getMessage().startsWith("CLIENT CSR truncated (10 of"));
        verify(certs, never()).writeCsrHex(any(), any());

        when(chip.clientCsrPub()).thenReturn(CSR);
        assertArrayEquals(CSR, ChipInit.exportClientCsr(chip, certs, Path.of("cert.pem")));
        verify(certs).writeCsrHex(Path.of("cert.pem").resolve("client-csr.hex"), CSR);
    }

    @Test
    void insertSignedCsrReturnsDeviceMessage() throws Exception {
        when(chip.manage(eq(SeManage.CMD_INSERT_SIGNED_CSR), isNull(), any()))
                .thenReturn(new SeManage.Reply(SeManage.OK, "INSERT SIGNED CSR ok"));
        ChipInit.EnrollResult r = ChipInit.insertSignedCsr(chip, new byte[] {0x30, 0x00});
        assertTrue(r.ok());
        assertEquals("INSERT SIGNED CSR ok", r.message());
    }


    @Test
    void readPairingKeyHexRejectsMalformedFiles(@TempDir Path dir) throws Exception {
        Path twoLines = dir.resolve("a.hex");
        Files.writeString(twoLines, "1\nabcd\n");
        assertThrows(IOException.class, () -> ChipInit.readPairingKeyHex(twoLines));

        Path badSlot = dir.resolve("b.hex");
        Files.writeString(badSlot, "one\n" + "00".repeat(32) + "\n" + "11".repeat(32) + "\n");
        assertThrows(IOException.class, () -> ChipInit.readPairingKeyHex(badSlot));

        Path badHex = dir.resolve("c.hex");
        Files.writeString(badHex, "1\nzz\n" + "11".repeat(32) + "\n");
        assertThrows(IOException.class, () -> ChipInit.readPairingKeyHex(badHex));
    }

    @Test
    void fileCertsBasics(@TempDir Path dir) throws Exception {
        ChipInit.Certs files = ChipInit.FILE_CERTS;
        assertFalse(files.isRegularFile(null));
        assertFalse(files.isRegularFile(dir.resolve("nope")));
        assertEquals(Optional.empty(), files.loadDerIfPresent(dir.resolve("nope.pem")));

        Path csr = dir.resolve("sub").resolve("client-csr.hex");
        files.writeCsrHex(csr, new byte[] {1, 2});
        assertEquals("0102\n", Files.readString(csr));
        assertTrue(files.isRegularFile(csr));

        Path key = dir.resolve("pairing-key.hex");
        byte[] priv = filled(SeConstants.PAIRING_KEY_LEN, (byte) 3);
        byte[] pub = filled(SeConstants.PAIRING_KEY_LEN, (byte) 4);
        files.writePairingKeyHex(key, 2, priv, pub);
        SeManage.PairingKey back = ChipInit.readPairingKeyHex(key);
        assertEquals(2, back.slot());
        assertArrayEquals(priv, back.priv());
        assertArrayEquals(pub, back.pub());
    }


    private static ChipInit.EnrollRequest request(Optional<Integer> slot, Path caP12, String caPw) {
        return new ChipInit.EnrollRequest(PW, "12345678", slot, Path.of("client", "client-cert.pem"),
                caP12, caPw, "device", SPKI, new byte[] {0x30, 0x00});
    }

    private static byte[] filled(int n, byte v) {
        byte[] b = new byte[n];
        Arrays.fill(b, v);
        return b;
    }
}