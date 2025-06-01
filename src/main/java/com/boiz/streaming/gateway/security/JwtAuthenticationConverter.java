package com.boiz.streaming.gateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationConverter implements ServerAuthenticationConverter {

    private static final String BEARER = "Bearer ";
    private static final String AUTH_TOKEN = "AuthToken";

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String token;
        HttpCookie tokenCookie = exchange.getRequest().getCookies().getFirst(AUTH_TOKEN);

        if (Objects.nonNull(tokenCookie) && !tokenCookie.getValue().isEmpty()) {
            token = tokenCookie.getValue();

            if (!jwtTokenProvider.validateAccessToken(token)) {
                exchange.getResponse().addCookie(ResponseCookie.from(AUTH_TOKEN, "")
                        .httpOnly(true)
                        .secure(true)
                        .path("/")
                        .maxAge(3600)
                        .build()
                );
                token = null;
            }
        } else {
            token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        }

        if (Objects.nonNull(token) && token.startsWith(BEARER)) {
            token = token.substring(BEARER.length());
        }

        final UserDetails userDetails = createUserDetails(token);

        if (Objects.isNull(token) || Objects.isNull(userDetails)) {
            return Mono.empty();
        }

        return Mono.just(token).map(t -> JwtToken.of(t, userDetails));
    }

    private UserDetails createUserDetails(final String token) {
        if (Objects.isNull(token) || token.isEmpty()) {
            return null;
        }

        final String email = jwtTokenProvider.getEmailFromAccessToken(token);
        final String password = jwtTokenProvider.getPasswordFromAccessToken(token);
        final String role = jwtTokenProvider.getRoleFromAccessToken(token);

        return org.springframework.security.core.userdetails.User.builder()
                .username(email)
                .password(password)
                .authorities(role.startsWith("ROLE_") ? role : "ROLE_%s".formatted(role))
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(false)
                .build();
    }
}
