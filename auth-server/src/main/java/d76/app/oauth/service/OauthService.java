package d76.app.oauth.service;

import d76.app.auth.dto.response.RegisterResponse;
import d76.app.auth.model.AuthAttributes;
import d76.app.auth.model.IdentityProvider;
import d76.app.oauth.dto.SocialRegisterRequest;
import d76.app.security.jwt.JwtService;
import d76.app.security.jwt.model.JwtPurpose;
import d76.app.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OauthService {

    private final UserService userService;
    private final JwtService jwtService;

    public RegisterResponse socialRegister(SocialRegisterRequest request) {

        var claims = jwtService.extractClaims(request.actionToken());
        jwtService.assertActionTokenValid(claims, JwtPurpose.SOCIAL_REGISTER);

        String email = claims.getSubject();
        var provider = IdentityProvider.fromClient(
                claims.get(AuthAttributes.IDENTITY_PROVIDER, String.class));

        var user = userService.createOAuthUser(email, request.userName(), provider);

        return new RegisterResponse(user.getEmail(), provider.name(), user.getCreatedAt());
    }
}