package d76.app.security.jwt;

import d76.app.auth.exception.AuthErrorCode;
import d76.app.auth.model.AuthAttributes;
import d76.app.security.jwt.model.JwtPurpose;
import d76.app.security.principal.UserPrincipal;
import dev.d76.spring.exception.BusinessException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

@Slf4j
@Service
public class JwtService {

    private final long accessTokenTTLSeconds;

    private final long actionTokenTTLSeconds;
    private final long reAuthTokenTTLSeconds;

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private final String TOKEN_ISSUER = "d76-auth-server";

    JwtService(
            @Value("${application.jwt.privateKey}") String privateKeyPath,
            @Value("${application.jwt.publicKey}") String publicKeyPath,
            @Value("${application.jwt.token.access.seconds}") long accessTokenTTLSeconds,
            @Value("${application.jwt.token.action.seconds}") long actionTokenTTLSeconds,
            @Value("${application.jwt.token.reAuth.seconds}") long reAuthTokenTTLSeconds
    ) {

        try {
            this.privateKey = loadPrivateKey(privateKeyPath);
            this.publicKey = loadPublicKey(publicKeyPath);
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to load RSA key files. Check jwt.privateKey and jwt.publicKey paths. Path attempted: "
                            + privateKeyPath, e);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(
                    "RSA key files found but could not be parsed. Ensure keys are PKCS8 (private) and X509 (public) PEM format.", e);
        }

        this.accessTokenTTLSeconds = accessTokenTTLSeconds;
        this.actionTokenTTLSeconds = actionTokenTTLSeconds;
        this.reAuthTokenTTLSeconds = reAuthTokenTTLSeconds;
    }

    private PrivateKey loadPrivateKey(String privateKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String key = Files.readString(Path.of(privateKeyPath));

        key = key.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        var decoded = Base64.getDecoder().decode(key);
        var spec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private PublicKey loadPublicKey(String publicKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String key = Files.readString(Path.of(publicKeyPath));

        key = key.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        var decoded = Base64.getDecoder().decode(key);
        var spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    /**
     * ACCESS TOKEN
     */
    public String generateAccessToken(UserPrincipal principal) {

        String jti = UUID.randomUUID().toString();

        List<String> role = principal.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Jwts.builder()
                .id(jti)
                .subject(String.valueOf(principal.getUserId()))
                .claim(AuthAttributes.EMAIL, principal.getUsername())
                .claim(AuthAttributes.IDENTITY_PROVIDER, principal.getIdentityProvider().name())
                .claim(AuthAttributes.ROLES, role)
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(accessTokenTTLSeconds)))
                .signWith(getPrivateKey(), Jwts.SIG.RS256)
                .issuer(TOKEN_ISSUER)
                .compact();
    }

    /**
     * ACTION TOKEN
     */

    public String generateActionToken(String email, JwtPurpose purpose, String identityProvider) {

        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .id(jti)
                .subject(email)
                .claim(AuthAttributes.TOKEN_PURPOSE, purpose.name())
                .claim(AuthAttributes.IDENTITY_PROVIDER, identityProvider)
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(actionTokenTTLSeconds))) // 5 mins
                .signWith(getPrivateKey(), Jwts.SIG.RS256)
                .issuer(TOKEN_ISSUER)
                .compact();
    }

    public void assertActionTokenValid(Claims claims, JwtPurpose expectedPurpose) {
        boolean purposeMatches = expectedPurpose.name()
                .equals(claims.get(AuthAttributes.TOKEN_PURPOSE, String.class));
        boolean notExpired = new Date().before(claims.getExpiration());

        if (!purposeMatches || !notExpired) {
            String reason = !purposeMatches ? "purpose_mismatch" : "expired";
            log.warn("Action token rejected for user={} reason={} expectedPurpose={}",
                    claims.getSubject(), reason, expectedPurpose);
            throw new BusinessException(AuthErrorCode.INVALID_TOKEN);
        }
    }

    /**
     * RE_AUTH TOKEN
     */
    public String generateReAuthToken(String email, JwtPurpose jwtPurpose) {
        return Jwts
                .builder()
                .id(UUID.randomUUID().toString())
                .subject(email)
                .claim(AuthAttributes.TOKEN_PURPOSE, jwtPurpose.name())
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(reAuthTokenTTLSeconds))) // 3 mins
                .issuer(TOKEN_ISSUER)
                .signWith(getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    public void assertReAuthTokenValid(Claims claims, String email, JwtPurpose expectedPurpose) {
        boolean subjectMatches = email.equals(claims.getSubject());
        boolean purposeMatches = expectedPurpose.name()
                .equals(claims.get(AuthAttributes.TOKEN_PURPOSE, String.class));
        boolean notExpired = new Date().before(claims.getExpiration());

        if (!subjectMatches || !purposeMatches || !notExpired) {
            String reason = !purposeMatches ? "purpose_mismatch"
                    : !subjectMatches ? "subject_mismatch"
                    : "expired";
            log.warn("ReAuth token rejected for user={} reason={} expectedPurpose={}",
                    claims.getSubject(), reason, expectedPurpose);
            throw new BusinessException(AuthErrorCode.INVALID_TOKEN);
        }
    }

    /**
     * CORE
     */
    public Claims extractClaims(String token) {
        try {
            return Jwts
                    .parser()
                    .requireIssuer(TOKEN_ISSUER)
                    .verifyWith(getPublicKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

        } catch (JwtException ex) {
            log.warn("JWT parsing/verification failed: {}", ex.getMessage(), ex);
            throw new BusinessException(
                    AuthErrorCode.INVALID_TOKEN,
                    "Invalid or tampered token"
            );
        }
    }

    private PublicKey getPublicKey() {
        return publicKey;
    }

    private PrivateKey getPrivateKey() {
        return privateKey;
    }
}
