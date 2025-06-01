package com.boiz.streaming.gateway.security;

import com.boiz.streaming.gateway.config.JwtAccessSecretProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;

@Service
@Slf4j
public class JwtTokenProvider {

    private static final String ROLE = "role";
    private static final String PASSWORD = "password";

    private final JwtAccessSecretProperties properties;

    private SecretKey jwtAccessSecretKey;

    @Autowired
    public JwtTokenProvider(final JwtAccessSecretProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    private void init() {
        this.jwtAccessSecretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(properties.secret()));
    }

    public String getEmailFromAccessToken(final String accessToken) {
        return getAccessClaims(accessToken).getSubject();
    }

    public String getPasswordFromAccessToken(final String accessToken) {
        return getAccessClaims(accessToken).get(PASSWORD, String.class);
    }

    public String getRoleFromAccessToken(final String accessToken) {
        return getAccessClaims(accessToken).get(ROLE, String.class);
    }

    public boolean validateAccessToken(final String accessToken) {
        return validateToken(accessToken, jwtAccessSecretKey);
    }

    private Claims getAccessClaims(@NonNull final String accessToken) {
        return getClaims(accessToken, jwtAccessSecretKey);
    }

    private Claims getClaims(@NonNull final String token, @NonNull final Key secret) {
        return Jwts.parserBuilder()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean validateToken(@NonNull final String token, @NonNull Key secretKey) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception ex) {
            log.warn("Token validation error: {}", ex.getMessage());
            return false;
        }
    }

}
