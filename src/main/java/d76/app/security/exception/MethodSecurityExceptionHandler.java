package d76.app.security.exception;

import d76.app.auth.exception.AuthErrorCode;
import dev.d76.spring.exception.autoconfigure.web.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.NullMarked;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@NullMarked @Order(value = 1)
public class MethodSecurityExceptionHandler {

    /**
     * Triggered when accessing a resource without permission
     * User is authenticated, but lacks role/authority
     * level: method level
     */

    @ExceptionHandler(AuthorizationDeniedException.class)
    ResponseEntity<ApiErrorResponse> handleAuthorizationDeniedException(AuthorizationDeniedException ex, HttpServletRequest request) {

        AuthErrorCode errorCode = AuthErrorCode.ACCESS_DENIED;
        var errorResponse = ApiErrorResponse.builderFrom(errorCode, request).build();
        return ResponseEntity.status(errorCode.getHttpStatus()).body(errorResponse);
    }
}
