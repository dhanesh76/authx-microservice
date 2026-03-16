package d76.app.user.exception;

import org.springframework.http.HttpStatus;

public enum UserErrorCode implements dev.d76.spring.exception.ErrorCode {

    //USER
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "No account is associated with this email address."),

    //OAUTH
    AUTH_PROVIDER_ALREADY_LINKED(HttpStatus.CONFLICT, "IdentityProvider is already linked with account"),

    //PASSWORD
    INCORRECT_PASSWORD(HttpStatus.CONFLICT, "Incorrect Password"),
    SAME_PASSWORD(HttpStatus.CONFLICT, "New password cannot be same as the old password");

    private final HttpStatus status;
    private final String defaultMessage;

    UserErrorCode(HttpStatus status, String defaultMessage) {
        this.status = status;
        this.defaultMessage = defaultMessage;
    }

    @Override
    public int getHttpStatus() {
        return status.value();
    }

    @Override
    public String defaultMessage() {
        return defaultMessage;
    }
}
