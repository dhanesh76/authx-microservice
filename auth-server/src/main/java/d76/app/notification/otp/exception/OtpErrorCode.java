package d76.app.notification.otp.exception;


import dev.d76.spring.exception.ErrorCode;
import org.springframework.http.HttpStatus;

public enum OtpErrorCode implements ErrorCode {
    OTP_EXPIRED(HttpStatus.BAD_REQUEST, "The OTP has expired. Please request a new code."),
    INVALID_OTP(HttpStatus.BAD_REQUEST, "The OTP is incorrect. Please check the code you entered.");

    private final String defaultMessage;
    private final HttpStatus status;

    OtpErrorCode(HttpStatus status, String defaultMessage) {
        this.defaultMessage = defaultMessage;
        this.status = status;
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
