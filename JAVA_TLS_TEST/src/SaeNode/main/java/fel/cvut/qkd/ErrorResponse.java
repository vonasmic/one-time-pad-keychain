package fel.cvut.qkd;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    public String message;
    public List<Map<String, Object>> details;
}
