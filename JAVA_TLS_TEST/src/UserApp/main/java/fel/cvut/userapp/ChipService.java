package fel.cvut.userapp;

import fel.cvut.se.SeManage;
import fel.cvut.se.SeUsbDump;
import fel.cvut.se.SecureOtp;
import fel.cvut.usb.SeUsbLink;
import fel.cvut.usb.SeUsbTls;

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

    SeUsbDump otpLeft() throws Exception {
        return usb.transactDump("TROPIC OTP LEFT");
    }

    SeUsbDump peerList() throws Exception {
        return usb.transactDump("PEER LIST");
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

    SeUsbDump dump(String command) throws Exception {
        return usb.transactDump(command);
    }

    void transact(String line) throws Exception {
        usb.resetConsole();
        usb.transact(line);
    }
}
