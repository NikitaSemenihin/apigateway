package com.innowise.apigateway.security;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class JwtServerAuthenticationConverter implements ServerAuthenticationConverter {

    private static final String BEARER_PREFIX = "Bearer ";

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        if (SecurityPaths.isPublic(exchange.getRequest())) {
            return Mono.empty();
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return Mono.empty();
        }

        String token = authHeader.substring(BEARER_PREFIX.length());
        return Mono.just(UsernamePasswordAuthenticationToken.unauthenticated(token, token));
    }
}
