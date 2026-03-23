package d76.app.oauth.exception;

import d76.app.auth.model.AuthAttributes;
import d76.app.auth.model.IdentityProvider;
import dev.d76.spring.exception.ErrorCode;
import lombok.Getter;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Getter
public class OAuth2FlowException extends OAuth2AuthenticationException {

    private final Map<String, Object> meta;

    public OAuth2FlowException(ErrorCode errorCode,
                               String email,
                               IdentityProvider provider) {
        super(new OAuth2Error(errorCode.getErrorCode()));
        this.meta = buildMeta(email, provider);
    }

    private static Map<String, Object> buildMeta(String email, IdentityProvider provider) {
        var meta = new HashMap<String, Object>();

        meta.put(AuthAttributes.IDENTITY_PROVIDER, provider.name());
        Optional.ofNullable(email).ifPresent(e -> meta.put(AuthAttributes.EMAIL, e));

        return Collections.unmodifiableMap(meta);
    }
}
