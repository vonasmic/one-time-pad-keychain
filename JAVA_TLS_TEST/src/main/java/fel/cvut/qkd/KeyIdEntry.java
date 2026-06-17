package fel.cvut.qkd;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class KeyIdEntry {
    public String key_ID;
    public Map<String, Object> key_ID_extension;
}
