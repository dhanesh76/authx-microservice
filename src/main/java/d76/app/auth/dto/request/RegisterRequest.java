package d76.app.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import org.hibernate.validator.constraints.Length;

public record RegisterRequest(
        @NotEmpty(message = "username cannot be empty")
        String userName,

        @Email
        String email,

        @NotEmpty(message = "password cannot be empty")
        @Length(min = 8)
        String password
) {
}
