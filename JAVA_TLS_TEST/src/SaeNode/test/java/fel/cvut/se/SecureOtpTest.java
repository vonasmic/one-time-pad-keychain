package fel.cvut.se;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecureOtpTest {

    @Test
    void encryptRequestRoundTripKeepsPinAndPlaintext() {
        byte[] pin = "1234".getBytes(StandardCharsets.US_ASCII);
        byte[] plaintext = "hello-otp".getBytes(StandardCharsets.UTF_8);
        byte[] wire = SecureOtp.encodeEncryptRequest(pin, plaintext);

        assertEquals(pin.length, wire[0] & 0xFF);
        assertArrayEquals(pin, java.util.Arrays.copyOfRange(wire, 1, 1 + pin.length));
        int msgOff = 1 + pin.length;
        int msgLen = (wire[msgOff] & 0xFF)
                | ((wire[msgOff + 1] & 0xFF) << 8)
                | ((wire[msgOff + 2] & 0xFF) << 16)
                | ((wire[msgOff + 3] & 0xFF) << 24);
        assertEquals(plaintext.length, msgLen);
        assertArrayEquals(
                plaintext,
                java.util.Arrays.copyOfRange(wire, msgOff + 4, msgOff + 4 + msgLen));
    }

    @Test
    void encryptReplyRoundTripPreservesSlotsAndChunks() throws Exception {
        SecureOtp.EncryptReply reply = new SecureOtp.EncryptReply(List.of(
                new SecureOtp.EncryptPad(0, new byte[] {1, 2, 3}),
                new SecureOtp.EncryptPad(7, new byte[] {9})
        ));
        byte[] wire = reply.toBytes();
        SecureOtp.EncryptReply decoded = SecureOtp.decodeEncryptReply(wire);
        assertEquals(2, decoded.pads().size());
        assertEquals(0, decoded.pads().get(0).logicalSlot());
        assertArrayEquals(new byte[] {1, 2, 3}, decoded.pads().get(0).chunk());
        assertEquals(7, decoded.pads().get(1).logicalSlot());
        assertArrayEquals(new byte[] {9}, decoded.pads().get(1).chunk());
    }

    @Test
    void decryptRequestPrefixesPinOntoEncryptReply() {
        byte[] encryptReply = SecureOtp.encodeEncryptReply(new SecureOtp.EncryptReply(List.of(
                new SecureOtp.EncryptPad(1, new byte[] {4, 5})
        )));
        byte[] wire = SecureOtp.encodeDecryptRequest("9999", encryptReply);
        assertEquals(4, wire[0] & 0xFF);
        assertArrayEquals("9999".getBytes(StandardCharsets.US_ASCII),
                java.util.Arrays.copyOfRange(wire, 1, 5));
        assertArrayEquals(encryptReply, java.util.Arrays.copyOfRange(wire, 5, wire.length));
    }

    @Test
    void decryptReplyConcatenatesChunks() throws Exception {
        byte[] wire = SecureOtp.encodeDecryptReply(new SecureOtp.DecryptReply(List.of(
                "ab".getBytes(StandardCharsets.UTF_8),
                "cd".getBytes(StandardCharsets.UTF_8)
        )));
        SecureOtp.DecryptReply decoded = SecureOtp.decodeDecryptReply(wire);
        assertEquals(2, decoded.chunks().size());
        assertArrayEquals("abcd".getBytes(StandardCharsets.UTF_8), decoded.plaintext());
    }

    @Test
    void encryptReplyReadDoesNotRequireEof() throws Exception {
        byte[] reply = SecureOtp.encodeEncryptReply(new SecureOtp.EncryptReply(List.of(
                new SecureOtp.EncryptPad(0, new byte[] {8})
        )));
        byte[] withTrailing = new byte[reply.length + 3];
        System.arraycopy(reply, 0, withTrailing, 0, reply.length);
        SecureOtp.EncryptReply decoded =
                SecureOtp.readEncryptReply(new ByteArrayInputStream(withTrailing));
        assertEquals(1, decoded.pads().size());
        assertArrayEquals(new byte[] {8}, decoded.pads().get(0).chunk());
    }

    @Test
    void pinMustBeFourToEightBytes() {
        byte[] plaintext = new byte[] {1};
        assertThrows(IllegalArgumentException.class,
                () -> SecureOtp.encodeEncryptRequest("12", plaintext));
        assertThrows(IllegalArgumentException.class,
                () -> SecureOtp.encodeEncryptRequest("123456789", plaintext));
        SecureOtp.encodeEncryptRequest("1234", plaintext);
        SecureOtp.encodeEncryptRequest("12345678", plaintext);
    }

    @Test
    void emptyPlaintextIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> SecureOtp.encodeEncryptRequest("1234", new byte[0]));
    }

    @Test
    void zeroPadCountIsRejected() {
        byte[] empty = new byte[] {0, 0, 0, 0};
        assertThrows(IOException.class, () -> SecureOtp.decodeEncryptReply(empty));
        assertThrows(IOException.class, () -> SecureOtp.decodeDecryptReply(empty));
    }

    @Test
    void errorReplyThrowsOtpExceptionWithCode() {
        byte[] wire = new byte[] {0, 0, 0, 0, 1, 0, 0, 0};
        SecureOtp.OtpException enc = assertThrows(SecureOtp.OtpException.class,
                () -> SecureOtp.decodeEncryptReply(wire));
        assertEquals(SecureOtp.ERR_EXHAUSTED, enc.code());
        SecureOtp.OtpException dec = assertThrows(SecureOtp.OtpException.class,
                () -> SecureOtp.decodeDecryptReply(wire));
        assertEquals(SecureOtp.ERR_EXHAUSTED, dec.code());
        assertEquals("EXHAUSTED", SecureOtp.OtpException.nameFor(enc.code()));
    }
}
