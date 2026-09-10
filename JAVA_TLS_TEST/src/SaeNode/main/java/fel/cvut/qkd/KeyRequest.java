package fel.cvut.qkd;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class KeyRequest {
    public Integer number;
    public Integer size;
    public List<String> additional_slave_SAE_IDs;
    public List<Map<String, Object>> extension_mandatory;
    public List<Map<String, Object>> extension_optional;

    public static KeyRequest empty() {
        return new KeyRequest();
    }

    public boolean isSimpleGetEligible() {
        return (additional_slave_SAE_IDs == null || additional_slave_SAE_IDs.isEmpty())
                && (extension_mandatory == null || extension_mandatory.isEmpty())
                && (extension_optional == null || extension_optional.isEmpty());
    }
}
