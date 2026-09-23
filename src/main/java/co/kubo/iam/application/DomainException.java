package co.kubo.iam.application;

/** Error de negocio con codigo estable para el cliente y su codigo HTTP asociado. */
public class DomainException extends RuntimeException {

    private final String code;
    private final int status;

    public DomainException(String code, String message, int status) {
        super(message);
        this.code = code;
        this.status = status;
    }

    public static DomainException badRequest(String code, String message) {
        return new DomainException(code, message, 400);
    }

    public static DomainException unauthorized(String code, String message) {
        return new DomainException(code, message, 401);
    }

    public static DomainException conflict(String code, String message) {
        return new DomainException(code, message, 409);
    }

    public static DomainException notFound(String code, String message) {
        return new DomainException(code, message, 404);
    }

    public String getCode() {
        return code;
    }

    public int getStatus() {
        return status;
    }
}
