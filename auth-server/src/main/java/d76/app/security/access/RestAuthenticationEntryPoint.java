package d76.app.security.access;

import com.fasterxml.jackson.databind.ObjectMapper;
import d76.app.auth.exception.AuthErrorCode;
import dev.d76.spring.exception.autoconfigure.web.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@NullMarked
@RequiredArgsConstructor
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    /**
     * Triggered when accessing a protected resource without being logged-in
     * User is anonymous / session expired / no token
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException {

        AuthErrorCode errorCode = AuthErrorCode.INVALID_CREDENTIALS;
        var errorResponse = ApiErrorResponse.builderFrom(errorCode, request).build();

        response.setStatus(errorResponse.httpStatusCode());
        response.setContentType(MediaType.APPLICATION_JSON.getType());
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
