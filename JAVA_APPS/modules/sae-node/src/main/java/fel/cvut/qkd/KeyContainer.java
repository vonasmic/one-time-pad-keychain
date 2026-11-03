package fel.cvut.qkd;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class KeyContainer {
    public List<KeyItem> keys;
    public Map<String, Object> key_container_extension;
}
