package fel.cvut.qorum;

public class PqcCryptoUtil {
    // Stub: Replace with your actual WolfSSL signing logic
    public static byte[] signMessage(String data) {
        return ("SIGNED_" + data).getBytes();
    }

    // Stub: Replace with your actual WolfSSL verification logic
    public static boolean verifySignature(String expectedData, byte[] signature, String signerId) {
        String reconstructedSig = new String(signature);
        return reconstructedSig.equals("SIGNED_" + expectedData);
    }
}