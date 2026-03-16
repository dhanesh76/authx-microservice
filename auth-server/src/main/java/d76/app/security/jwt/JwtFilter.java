package d76.app.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import d76.app.auth.model.AuthAttributes;
import d76.app.auth.model.IdentityProvider;
import d76.app.security.principal.UserPrincipal;
import dev.d76.spring.exception.BusinessException;
import dev.d76.spring.exception.autoconfigure.web.ApiErrorResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Component
@NullMarked
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);

            if (header != null && header.startsWith("Bearer ") &&
                    SecurityContextHolder.getContext().getAuthentication() == null) {

                String accessToken = header.substring("Bearer ".length()).trim();

                var claims = jwtService.extractClaims(accessToken);

                var userId = Long.parseLong(claims.getSubject());
                var email = claims.get(AuthAttributes.EMAIL, String.class);
                var identityProvider = IdentityProvider.fromClient(
                        claims.get(AuthAttributes.IDENTITY_PROVIDER, String.class)
                );

                List<SimpleGrantedAuthority> authorities = claims
                        .get(AuthAttributes.ROLES) instanceof List<?> roleClaim ?
                        roleClaim
                                .stream()
                                .filter(String.class::isInstance)
                                .map(String.class::cast)
                                .map(SimpleGrantedAuthority::new)
                                .toList()
                        : List.of();

                var userPrincipal = UserPrincipal.fromJwt(userId, email, identityProvider, authorities);
                var authenticationToken = UsernamePasswordAuthenticationToken.authenticated(
                        userPrincipal,
                        null,
                        authorities
                );

                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
            filterChain.doFilter(request, response);
        } catch (BusinessException e) {
            var errorCode = e.getErrorCode();

            response.setStatus(errorCode.getHttpStatus());
            response.setContentType(MediaType.APPLICATION_JSON.getType());

            var errorResponse = ApiErrorResponse.builderFrom(errorCode, request).build();
            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        }
    }
}
