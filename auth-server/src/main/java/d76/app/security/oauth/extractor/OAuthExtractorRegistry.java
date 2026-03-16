package d76.app.security.oauth.extractor;

import d76.app.auth.model.IdentityProvider;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class OAuthExtractorRegistry {

    private final Map<IdentityProvider, OAuthUserExtractor> oAuthUserExtractors;

    public OAuthExtractorRegistry(List<OAuthUserExtractor> oAuthUserExtractors) {
        this.oAuthUserExtractors = oAuthUserExtractors
                .stream()
                .collect(Collectors
                        .toMap(OAuthUserExtractor::identityProvider, Function.identity())
                );
    }

    public OAuthUserExtractor resolve(IdentityProvider provider) {
        OAuthUserExtractor extractor = oAuthUserExtractors.get(provider);
        if (extractor == null) {
            throw new IllegalStateException(
                    "No OAuth extractor registered for provider: " + provider
            );
        }
        return extractor;
    }
}
