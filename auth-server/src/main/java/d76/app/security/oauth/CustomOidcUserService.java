package d76.app.security.oauth;

import d76.app.auth.model.IdentityProvider;
import d76.app.security.oauth.extractor.OAuthExtractorRegistry;
import d76.app.security.principal.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOidcUserService extends OidcUserService {

    private final OAuthAccountVerifier accountVerifier;
    private final OAuthExtractorRegistry extractorRegistry;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {

        var oidcUser = super.loadUser(userRequest);

        IdentityProvider identityProvider = IdentityProvider.fromClient(
                userRequest.getClientRegistration().getRegistrationId());

        // route through registry — consistent with OAuth2 flow
        var extractor = extractorRegistry.resolve(identityProvider);
        var userInfo = extractor.extract(userRequest, oidcUser);

        var user = accountVerifier.verifyUser(userInfo.email(), identityProvider);

        return UserPrincipal.fromOidc(
                user, identityProvider,
                userInfo.claims(),
                userRequest.getIdToken(),
                oidcUser.getUserInfo());
    }
}