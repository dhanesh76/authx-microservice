package d76.app.security.oauth;

import d76.app.auth.exception.AuthErrorCode;
import d76.app.auth.model.IdentityProvider;
import d76.app.oauth.exception.OAuth2FlowException;
import d76.app.user.entity.Users;
import d76.app.user.exception.UserErrorCode;
import d76.app.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuthAccountVerifier {

    private final UserService userService;

    public Users verifyUser(String email, IdentityProvider provider) {

        /*
         * exception scenarios
         *   - email missing
         *   - email not registered
         *   - identity provider mismatch
         * */

        if (email == null) {
            throw new OAuth2FlowException(AuthErrorCode.EMAIL_REQUIRED, null, provider);
        }

        var user = userService
                .findUserByEmail(email)
                .orElseThrow(() ->
                        new OAuth2FlowException(UserErrorCode.USER_NOT_FOUND, email, provider)
                );

        if (!user.getIdentityProviders().contains(provider))
            throw new OAuth2FlowException(AuthErrorCode.AUTH_PROVIDER_NOT_LINKED, email, provider);

        return user;
    }
}