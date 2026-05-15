package fel.cvut.qorum;

public class ClientRecord {

    private final String hash1;
    private final String hash2;
    private final String value;
    private final String signerId;

    public ClientRecord(String hash1, String hash2, String value, String signerId) {
        this.hash1 = hash1;
        this.hash2 = hash2;
        this.value = value;
        this.signerId = signerId;
    }

    public RecordKey createKey() {
        return new RecordKey(this.hash1, this.hash2);
    }

    public RecordPayload createPayload() {
        RecordKey key = createKey();
        String dataToSign = key.toString() + this.value;
        byte[] signature = PqcCryptoUtil.signMessage(dataToSign);
        return new RecordPayload(this.value, signature, this.signerId);
    }
}
