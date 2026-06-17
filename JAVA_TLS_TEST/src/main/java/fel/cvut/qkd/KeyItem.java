package fel.cvut.qkd;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class KeyItem {
    public String key_ID;
    public String key;
    public Map<String, Object> key_ID_extension;
    public Map<String, Object> key_extension;
}
