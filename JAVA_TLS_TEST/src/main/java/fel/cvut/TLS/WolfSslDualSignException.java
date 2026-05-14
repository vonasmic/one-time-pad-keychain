package fel.cvut.TLS;

public class WolfSslDualSignException extends RuntimeException {
    public WolfSslDualSignException(String message) {
        super(message);
    }

    public WolfSslDualSignException(String message, Throwable cause) {
        super(message, cause);
    }
}
