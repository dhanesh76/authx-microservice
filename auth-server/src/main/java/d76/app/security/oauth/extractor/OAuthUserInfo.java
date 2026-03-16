package d76.app.security.oauth.extractor;

import java.util.Map;

public record OAuthUserInfo(
        String email,
        Map<String, Object> claims
) {
}
