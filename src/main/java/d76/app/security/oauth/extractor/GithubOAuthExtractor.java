package d76.app.security.oauth.extractor;

import d76.app.auth.model.AuthAttributes;
import d76.app.auth.model.IdentityProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class GithubOAuthExtractor implements OAuthUserExtractor {

    private final RestClient restClient;

    @Override
    public IdentityProvider identityProvider() {
        return IdentityProvider.GITHUB;
    }

    @Override
    public OAuthUserInfo extract(OAuth2UserRequest request, OAuth2User oAuth2User) {

        String email = fetchPrimaryEmail(oAuth2User, request);

        var claims = new HashMap<>(oAuth2User.getAttributes());
        claims.put(AuthAttributes.EMAIL, email);

        return new OAuthUserInfo(email, claims);
    }

    private String fetchPrimaryEmail(OAuth2User oAuth2User, OAuth2UserRequest userRequest) {

        //if available with the public claims itself return
        if (oAuth2User.getAttribute(AuthAttributes.EMAIL) != null) {
            return oAuth2User.getAttribute(AuthAttributes.EMAIL);
        }

        //if not available publicly, fetch via the api using the accessToken
        String accessToken = userRequest.getAccessToken().getTokenValue();

        List<Map<String, Object>> userEmailEntries = restClient
                .get()
                .uri("https://api.github.com/emails")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .retrieve()
                .body(new ParameterizedTypeReference<>() {
                });

        //no email entries  found
        if (userEmailEntries == null) return null;

        return userEmailEntries.stream()
                .filter(emailEntry ->
                        Boolean.TRUE.equals(emailEntry.get("primary"))
                ).filter(emailEntry ->
                        Boolean.TRUE.equals(emailEntry.get("verified"))
                )
                .map(emailEntry -> emailEntry.get(AuthAttributes.EMAIL))
                .map(String.class::cast)
                .findFirst()
                .orElse(null);
    }
}
