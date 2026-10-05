package fel.cvut.qkd;

public class Qkd014ClientException extends Exception {
    private final int httpStatusCode;
    private final ErrorResponse errorResponse;

    public Qkd014ClientException(String message, Throwable cause) {
        super(message, cause);
        this.httpStatusCode = -1;
        this.errorResponse = null;
    }

    public Qkd014ClientException(String message, int httpStatusCode, ErrorResponse errorResponse) {
        super(message);
        this.httpStatusCode = httpStatusCode;
        this.errorResponse = errorResponse;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }

    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }
}
