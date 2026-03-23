package d76.app.security.oauth.extractor;

import d76.app.auth.model.IdentityProvider;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface OAuthUserExtractor {

    IdentityProvider identityProvider();

    OAuthUserInfo extract(OAuth2UserRequest request, OAuth2User oAuth2User);
}
