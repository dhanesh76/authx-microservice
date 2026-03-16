package d76.app.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import d76.app.auth.exception.AuthErrorCode;
import d76.app.auth.model.AuthAttributes;
import d76.app.oauth.exception.OAuth2FlowException;
import d76.app.security.jwt.JwtService;
import d76.app.security.jwt.model.JwtPurpose;
import d76.app.user.exception.UserErrorCode;
import dev.d76.spring.exception.ErrorCode;
import dev.d76.spring.exception.autoconfigure.web.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@NullMarked
@Component
@RequiredArgsConstructor
public class LoginFailureHandler implements AuthenticationFailureHandler {


    private final ObjectMapper objectMapper;
    private final JwtService jwtService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse res, AuthenticationException exception) throws IOException {

        //handle OAuth2Exception
        if (exception instanceof OAuth2FlowException ex) {
            String errorCode = ex.getError().getErrorCode();
            Map<String, Object> meta = ex.getMeta();

            String email = (String) meta.get(AuthAttributes.EMAIL);
            String identityProvider = (String) meta.get(AuthAttributes.IDENTITY_PROVIDER);

            if (errorCode.equals(AuthErrorCode.EMAIL_REQUIRED.name())) {

                var errorResponseBuilder = getBaseErrorResponseBuilder(
                        AuthErrorCode.EMAIL_REQUIRED, identityProvider, request);

                constructHttpResponse(res, errorResponseBuilder.build());
                return;
            }

            //prompt the user to link or not the account
            else if (errorCode.equals(AuthErrorCode.AUTH_PROVIDER_NOT_LINKED.name())) {

                var errorResponseBuilder = getBaseErrorResponseBuilder(AuthErrorCode.AUTH_PROVIDER_NOT_LINKED, identityProvider, request);

                var actionToken = jwtService
                        .generateActionToken(email, JwtPurpose.LINK_SOCIAL_ACCOUNT, identityProvider);

                errorResponseBuilder
                        .extension(AuthAttributes.ACTION_TOKEN, actionToken);

                constructHttpResponse(res, errorResponseBuilder.build());
                return;
            }

            //push the user to complete the registration
            else if (UserErrorCode.USER_NOT_FOUND.name().equals(errorCode)) {

                var errorResponseBuilder = getBaseErrorResponseBuilder(UserErrorCode.USER_NOT_FOUND, identityProvider, request);

                var actionToken = jwtService
                        .generateActionToken(email, JwtPurpose.SOCIAL_REGISTER, identityProvider);

                errorResponseBuilder
                        .extension(AuthAttributes.ACTION_TOKEN, actionToken);

                constructHttpResponse(res, errorResponseBuilder.build());
                return;
            }
        }

        var errorResponse = ApiErrorResponse
                .builderFrom(AuthErrorCode.INVALID_CREDENTIALS, request).build();

        constructHttpResponse(res, errorResponse);
    }

    private void constructHttpResponse(HttpServletResponse httpServletResponse, ApiErrorResponse errorResponse) throws IOException {
        httpServletResponse.setStatus(errorResponse.httpStatusCode());
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON.getType());
        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }

    private ApiErrorResponse.Builder getBaseErrorResponseBuilder(ErrorCode errorCode,
                                                                 String provider,
                                                                 HttpServletRequest request) {
        return ApiErrorResponse
                .builderFrom(errorCode, request)
                .extension(AuthAttributes.IDENTITY_PROVIDER, provider);
    }
}
