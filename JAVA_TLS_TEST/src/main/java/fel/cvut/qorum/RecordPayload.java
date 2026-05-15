package fel.cvut.qorum;

import org.infinispan.protostream.annotations.ProtoFactory;
import org.infinispan.protostream.annotations.ProtoField;

import java.io.Serializable;

public class RecordPayload implements Serializable {

    @ProtoField(number = 1)
    public final String jsonValue;

    @ProtoField(number = 2)
    public final byte[] signature;

    @ProtoField(number = 3)
    public final String signerId;

    @ProtoFactory
    public RecordPayload(String jsonValue, byte[] signature, String signerId) {
        this.jsonValue = jsonValue;
        this.signature = signature;
        this.signerId = signerId;
    }
}
