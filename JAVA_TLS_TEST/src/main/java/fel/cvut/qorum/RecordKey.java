package fel.cvut.qorum;

import org.infinispan.protostream.annotations.ProtoFactory;
import org.infinispan.protostream.annotations.ProtoField;

import java.io.Serializable;
import java.util.Objects;

public class RecordKey implements Serializable {

    private final String hash1;
    private final String hash2;

    @ProtoFactory
    public RecordKey(String hash1, String hash2) {
        this.hash1 = hash1;
        this.hash2 = hash2;
    }

    @ProtoField(number = 1)
    public String getHash1() {
        return hash1;
    }

    @ProtoField(number = 2)
    public String getHash2() {
        return hash2;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RecordKey key = (RecordKey) o;
        return Objects.equals(hash1, key.hash1)
                && Objects.equals(hash2, key.hash2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hash1, hash2);
    }

    @Override
    public String toString() {
        return hash1 + ":" + hash2;
    }
}
