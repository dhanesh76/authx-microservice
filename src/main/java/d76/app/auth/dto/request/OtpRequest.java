package d76.app.auth.dto.request;


import d76.app.notification.otp.model.OtpPurpose;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;


public record OtpRequest(
        @Email String email,
        @NotNull OtpPurpose purpose
) {
}
