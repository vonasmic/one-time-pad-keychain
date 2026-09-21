package fel.cvut.usb;

/**
 * Side channel from {@link UsbCdcRxMachine}: dump frames, pre-TLS ASCII, and ClientHello.
 */
public interface UsbCdcListener {

    void onDump(int status, byte[] body);

    void onPreTlsAscii(byte[] data, int off, int len);

    void onTlsHandshakeDetected();
}
