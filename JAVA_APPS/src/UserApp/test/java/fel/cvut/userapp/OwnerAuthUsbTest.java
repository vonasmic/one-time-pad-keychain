package fel.cvut.userapp;

import fel.cvut.se.SeBytes;
import fel.cvut.se.SeConstants;
import fel.cvut.usb.SeUsbLink;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Tag("unit")
class OwnerAuthUsbTest {

    private static final byte[] PW = "password".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SPKI = filled(SeConstants.MLDSA_PUB_LEN, (byte) 0x11);
    private static final byte[] SAE_CA = {0x30, 0x00};

    private SeUsbLink usb;
    private OwnerAuth auth;

    @BeforeEach
    void setUp() throws Exception {
        usb = mock(SeUsbLink.class);
        auth = new OwnerAuth(usb, SSLContext.getDefault());
    }


    @Test
    void ownerSetRefusedAtBeginNeverSendsBlob() throws Exception {
        when(usb.transact("OWNER SET")).thenReturn("refused\n");
        assertInstanceOf(ChipInit.OwnerSetResult.AlreadyEnrolled.class, auth.ownerSet(PW, SPKI, SAE_CA));
        verify(usb).resetConsole();
        verify(usb, never()).writeRaw(any());
    }

    @Test
    void ownerSetUnexpectedBeginFails() throws Exception {
        when(usb.transact("OWNER SET")).thenReturn("");
        ChipInit.OwnerSetResult r = auth.ownerSet(PW, SPKI, SAE_CA);
        assertEquals(new ChipInit.OwnerSetResult.Failed("failed"), r);
        verify(usb, never()).writeRaw(any());
    }

    @Test
    void ownerSetOkSendsBlobThenReadsApplyStatus() throws Exception {
        when(usb.transact("OWNER SET")).thenReturn("  OK \n");
        when(usb.readConsole(anyLong(), anyLong())).thenReturn("ok\n");
        assertInstanceOf(ChipInit.OwnerSetResult.Ok.class, auth.ownerSet(PW, SPKI, SAE_CA));
        var order = inOrder(usb);
        order.verify(usb).resetConsole();
        order.verify(usb).transact("OWNER SET");
        order.verify(usb).writeRaw(any());
        order.verify(usb).readConsole(SeUsbLink.CONSOLE_IDLE_MS, SeUsbLink.CONSOLE_SLOW_MAX_MS);
    }

    @Test
    void ownerSetApplyStatusIsClassified() throws Exception {
        when(usb.transact("OWNER SET")).thenReturn("ok");
        when(usb.readConsole(anyLong(), anyLong())).thenReturn("bad blob\n");
        assertEquals(new ChipInit.OwnerSetResult.Failed("bad blob"), auth.ownerSet(PW, SPKI, SAE_CA));
    }

    @Test
    void consoleHexQueriesMapEmptyFailedAndHex() throws Exception {
        when(usb.transact("TROPIC PUB")).thenReturn("empty\n");
        when(usb.transact("TROPIC KEM PUB")).thenReturn("0a0B\n");
        when(usb.transact("CLIENT HASH")).thenReturn(null);
        assertTrue(auth.tropicPub().isEmpty());
        assertArrayEquals(new byte[] {0x0a, 0x0b}, auth.tropicKemPub().orElseThrow());
        assertEquals(Optional.empty(), auth.clientHash());

        when(usb.transact("TROPIC PUB")).thenReturn("failed");
        assertThrows(IOException.class, auth::tropicPub);
        when(usb.transact("TROPIC PUB")).thenReturn("not-hex!");
        IOException notHex = assertThrows(IOException.class, auth::tropicPub);
        assertEquals("failed", notHex.getMessage());
    }

    @Test
    void clientCsrPubReassemblesHexAcrossChunks() throws Exception {
        byte[] pub = filled(SeConstants.MLDSA_PUB_LEN, (byte) 0x5a);
        pub[0] = 1;
        String hex = SeBytes.toHex(pub);
        int half = hex.length() / 2;
        when(usb.readConsole(anyLong(), anyLong())).thenReturn(hex.substring(0, half), hex.substring(half));
        assertArrayEquals(pub, auth.clientCsrPub());
        verify(usb).sendCommand("CLIENT CSR");
    }

    @Test
    void clientCsrPubFailsOnDeviceErrorEmptyOrTruncation() throws Exception {
        when(usb.readConsole(anyLong(), anyLong())).thenReturn("failed\n");
        assertEquals("failed", assertThrows(IOException.class, auth::clientCsrPub).getMessage());

        when(usb.readConsole(anyLong(), anyLong())).thenReturn("");
        assertEquals("failed", assertThrows(IOException.class, auth::clientCsrPub).getMessage());

        String shortHex = SeBytes.toHex(Arrays.copyOf(filled(16, (byte) 1), 16));
        when(usb.readConsole(anyLong(), anyLong())).thenReturn(shortHex, (String) null);
        IOException truncated = assertThrows(IOException.class, auth::clientCsrPub);
        assertTrue(truncated.getMessage().startsWith("CLIENT CSR truncated (16 of"), truncated.getMessage());
    }


    private static byte[] filled(int n, byte v) {
        byte[] b = new byte[n];
        Arrays.fill(b, v);
        return b;
    }
}