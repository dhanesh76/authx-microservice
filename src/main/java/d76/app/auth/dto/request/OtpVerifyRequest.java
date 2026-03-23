package d76.app.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public record OtpVerifyRequest(
        @Email String email,
        @Size(min = 6, max = 6) String otp
) {
}
