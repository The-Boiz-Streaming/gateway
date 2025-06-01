package com.boiz.streaming.gateway.security;

import com.boiz.streaming.gateway.exception.EmptyTokenException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication)
                .cast(JwtToken.class)
                .filter(jwtToken -> jwtTokenProvider.validateAccessToken(jwtToken.getToken()))
                .map(jwtToken -> jwtToken.withAuthenticated(true))
                .switchIfEmpty(Mono.error(EmptyTokenException.of()));

    }
}
