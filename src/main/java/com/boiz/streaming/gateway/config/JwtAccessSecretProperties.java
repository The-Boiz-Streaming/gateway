package com.boiz.streaming.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.jwt.access.token")
public record JwtAccessSecretProperties(String secret) {
}
