package fel.cvut.userapp;

import fel.cvut.se.SeManage;
import fel.cvut.se.SecureOtp;
import fel.cvut.usb.SeUsbLink;

import javax.net.ssl.SSLContext;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * USB chip operations. The REPL only parses; this class talks to the device.
 */
final class ChipService {

    private final SeUsbLink usb;
    private final SSLContext ctx;

    ChipService(SeUsbLink usb, SSLContext ctx) {
        this.usb = Objects.requireNonNull(usb, "usb");
        this.ctx = Objects.requireNonNull(ctx, "ctx");
    }

    byte[] encrypt(String pin, String message) throws Exception {
        byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
        return SeUsbTls.run(usb, ctx, "ENCRYPT", true, ssl -> {
            ssl.getOutputStream().write(SecureOtp.encodeEncryptRequest(pin, plaintext));
            ssl.getOutputStream().flush();
            return SecureOtp.readEncryptReply(ssl.getInputStream()).toBytes();
        });
    }

    byte[] decrypt(String pin, byte[] encryptReply) throws Exception {
        return SeUsbTls.run(usb, ctx, "DECRYPT", true, ssl -> {
            ssl.getOutputStream().write(SecureOtp.encodeDecryptRequest(pin, encryptReply));
            ssl.getOutputStream().flush();
            return SecureOtp.readDecryptReply(ssl.getInputStream()).plaintext();
        });
    }

    String otpStatus() throws Exception {
        return usb.transact("TROPIC OTP STATUS");
    }

    SeManage.Reply insertSignedCsr(byte[] certDer) throws Exception {
        return OwnerAuth.manage(
                usb, ctx, SeManage.CMD_INSERT_SIGNED_CSR, null,
                SeManage.encodeDeviceCertBody(certDer));
    }

    String peerList() throws Exception {
        return usb.transact("PEER LIST");
    }

    SeManage.Reply peerAdd(String pin, String name, byte[] hash) throws Exception {
        return OwnerAuth.manage(usb, ctx, SeManage.CMD_PEER_ADD, pin, SeManage.encodePeerAddBody(name, hash));
    }

    SeManage.Reply peerRemove(String pin, String name) throws Exception {
        return OwnerAuth.manage(usb, ctx, SeManage.CMD_PEER_REMOVE, pin, SeManage.encodePeerRemoveBody(name));
    }

    ChipInit.OwnerSetResult ownerSet(byte[] password, byte[] spki, byte[] saeCa) throws Exception {
        return OwnerAuth.ownerSet(usb, password, spki, saeCa);
    }

    SeManage.Reply ownerReplace(byte[] oldPassword, byte[] newPassword, byte[] ownerSpki) throws Exception {
        return OwnerAuth.manage(
                usb, ctx, SeManage.CMD_OWNER_REPLACE, null,
                SeManage.encodeOwnerReplaceBody(oldPassword, newPassword, ownerSpki));
    }

    String console(String command) throws Exception {
        return usb.transact(command, SeUsbLink.CONSOLE_IDLE_MS, SeUsbLink.CONSOLE_SLOW_MAX_MS);
    }

    String transact(String line) throws Exception {
        usb.resetConsole();
        return usb.transact(line);
    }
}
