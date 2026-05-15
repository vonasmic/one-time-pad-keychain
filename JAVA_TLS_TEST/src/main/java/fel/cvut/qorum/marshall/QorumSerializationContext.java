package fel.cvut.qorum.marshall;

import fel.cvut.qorum.RecordKey;
import fel.cvut.qorum.RecordPayload;
import org.infinispan.protostream.GeneratedSchema;
import org.infinispan.protostream.annotations.ProtoSchema;

@ProtoSchema(
        includeClasses = {
                RecordKey.class,
                RecordPayload.class
        },
        schemaFileName = "qorum.proto",
        schemaPackageName = "fel.cvut.qorum"
)
public interface QorumSerializationContext extends GeneratedSchema {
}
