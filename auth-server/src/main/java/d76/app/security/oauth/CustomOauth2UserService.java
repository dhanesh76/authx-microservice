package d76.app.security.oauth;


import d76.app.auth.model.IdentityProvider;
import d76.app.security.oauth.extractor.OAuthExtractorRegistry;
import d76.app.security.principal.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOauth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final OAuthAccountVerifier accountVerifier;
    private final OAuthExtractorRegistry oAuthExtractorRegistry;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        var delegate = new DefaultOAuth2UserService();
        var oAuth2User = delegate.loadUser(userRequest);

        var identityProvider = IdentityProvider.fromClient(
                userRequest.getClientRegistration().getRegistrationId()
        );

        var userExtractor = oAuthExtractorRegistry.resolve(identityProvider);

        var oAuthUserInfo = userExtractor.extract(userRequest, oAuth2User);
        var user = accountVerifier.verifyUser(oAuthUserInfo.email(), identityProvider);
        return UserPrincipal.fromOAuth2(user, identityProvider, oAuthUserInfo.claims());
    }
}