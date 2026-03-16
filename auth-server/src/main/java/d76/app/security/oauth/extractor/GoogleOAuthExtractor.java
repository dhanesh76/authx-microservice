package d76.app.security.oauth.extractor;

import d76.app.auth.model.AuthAttributes;
import d76.app.auth.model.IdentityProvider;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
public class GoogleOAuthExtractor implements OAuthUserExtractor {

    @Override
    public IdentityProvider identityProvider() {
        return IdentityProvider.GOOGLE;
    }

    @Override
    public OAuthUserInfo extract(OAuth2UserRequest request, OAuth2User oAuth2User) {
        // OIDC user guaranteed here — Google always goes through OidcUserService
        if (oAuth2User instanceof OidcUser oidcUser) {
            return new OAuthUserInfo(oidcUser.getEmail(), oidcUser.getAttributes());
        }
        // defensive — should never happen for Google
        String email = oAuth2User.getAttribute(AuthAttributes.EMAIL);
        return new OAuthUserInfo(email, oAuth2User.getAttributes());
    }
}