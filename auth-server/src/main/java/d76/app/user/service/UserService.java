package d76.app.user.service;

import d76.app.auth.exception.AuthErrorCode;
import d76.app.auth.model.IdentityProvider;
import d76.app.security.jwt.JwtService;
import d76.app.security.jwt.model.JwtPurpose;
import d76.app.user.dto.password.ChangePasswordRequest;
import d76.app.user.dto.password.VerifyPasswordResponse;
import d76.app.user.entity.Role;
import d76.app.user.entity.Users;
import d76.app.user.exception.UserErrorCode;
import d76.app.user.repo.RoleRepository;
import d76.app.user.repo.UsersRepository;
import dev.d76.spring.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final String DEFAULT_ROLE = "USER";

    private final UsersRepository usersRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public Users createLocalUser(String email, String username, String password) {
        assertEmailAvailable(email);
        assertUsernameAvailable(username);

        var user = Users.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .identityProviders(Set.of(IdentityProvider.EMAIL))
                .roles(new HashSet<>(Set.of(loadDefaultRole())))
                .build();

        return usersRepository.save(user);
    }

    @Transactional
    public Users createOAuthUser(String email, String username, IdentityProvider provider) {
        assertEmailAvailable(email);
        assertUsernameAvailable(username);

        var user = Users.builder()
                .username(username)
                .email(email)
                .identityProviders(Set.of(provider))
                .roles(Set.of(loadDefaultRole()))
                .build();

        return usersRepository.save(user);
    }

    @Transactional
    public void linkAuthProvider(String actionToken) {

        var claims = jwtService.extractClaims(actionToken);
        jwtService.assertActionTokenValid(claims, JwtPurpose.LINK_SOCIAL_ACCOUNT);

        var email = claims.getSubject();
        var provider = IdentityProvider.fromClient(
                claims.get("identityProvider", String.class));

        var user = loadUserByEmail(email);

        if (user.getIdentityProviders().contains(provider)) {
            throw new BusinessException(UserErrorCode.AUTH_PROVIDER_ALREADY_LINKED,
                    provider.name() + " is already linked to this account");
        }

        user.getIdentityProviders().add(provider);
        usersRepository.save(user);
    }

    @Transactional
    public void updatePassword(String email, String newPassword) {
        var user = loadUserByEmail(email);

        if (passwordEncoder.matches(newPassword, user.getPassword())) {
            throw new BusinessException(UserErrorCode.SAME_PASSWORD);
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        usersRepository.save(user);
    }

    @Transactional
    public void updatePassword(String email, ChangePasswordRequest request) {

        var claims = jwtService.extractClaims(request.reauthenticateToken());
        jwtService.assertReAuthTokenValid(claims, email, JwtPurpose.REAUTH);

        updatePassword(email, request.newPassword());
    }

    public VerifyPasswordResponse verify(String email, String password) {
        var user = loadUserByEmail(email);

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BusinessException(UserErrorCode.INCORRECT_PASSWORD);
        }

        var token = jwtService.generateReAuthToken(email, JwtPurpose.REAUTH);
        return new VerifyPasswordResponse(token, Instant.now());
    }

    public void assertEmailAvailable(String email) {
        if (usersRepository.existsByEmail(email)) {
            throw new BusinessException(AuthErrorCode.EMAIL_ALREADY_REGISTERED);
        }
    }

    public void assertUsernameAvailable(String username) {
        if (usersRepository.existsByUsername(username)) {
            throw new BusinessException(AuthErrorCode.USERNAME_TAKEN);
        }
    }

    public void assertUserExistByEmail(String email) {
        if (!usersRepository.existsByEmail(email)) {
            throw new BusinessException(UserErrorCode.USER_NOT_FOUND,
                    "No user exists with email: " + email);
        }
    }

    public boolean isUserNameAvailable(String username) {
        return !usersRepository.existsByUsername(username);
    }

    public Optional<Users> findUserByEmail(String email) {
        return usersRepository.findByEmail(email);
    }

    public Users loadUserByEmail(String email) {
        return usersRepository.findByEmail(email)
                .orElseThrow(() -> new BusinessException(
                        UserErrorCode.USER_NOT_FOUND, "No user exists with email: " + email));
    }

    public Users loadUserByEmailOrUsername(String usernameOrEmail) {
        return usersRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() -> new BusinessException(
                        UserErrorCode.USER_NOT_FOUND, "No user exists with: " + usernameOrEmail));
    }

    private Role loadDefaultRole() {
        return roleRepository.findByName(DEFAULT_ROLE)
                .orElseThrow(() -> new BusinessException(
                        AuthErrorCode.ROLE_NOT_FOUND, "Role not found: " + DEFAULT_ROLE));
    }
}