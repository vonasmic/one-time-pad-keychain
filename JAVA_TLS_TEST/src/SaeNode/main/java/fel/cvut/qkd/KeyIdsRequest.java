package fel.cvut.qkd;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class KeyIdsRequest {
    public List<KeyIdEntry> key_IDs;
    public Map<String, Object> key_IDs_extension;

    public static KeyIdsRequest fromKeyIds(List<String> keyIds) {
        KeyIdsRequest request = new KeyIdsRequest();
        request.key_IDs = new ArrayList<>(keyIds.size());
        for (String keyId : keyIds) {
            KeyIdEntry entry = new KeyIdEntry();
            entry.key_ID = keyId;
            request.key_IDs.add(entry);
        }
        return request;
    }
}
