package com.innowise.apigateway.security;

import com.innowise.apigateway.dto.TokenValidationResponse;
import com.innowise.apigateway.service.AuthValidationClient;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Set;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String USER_ROLE_HEADER = "X-User-Role";
    private static final String SERVICE_NAME_HEADER = "X-Service-Name";
    private static final Set<String> PUBLIC_PATHS = Set.of(
            "/api/auth/login",
            "/api/auth/register"
    );

    private final AuthValidationClient authValidationClient;

    public JwtAuthFilter(AuthValidationClient authValidationClient) {
        this.authValidationClient = authValidationClient;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        if (isPublicRequest(request)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return unauthorized(exchange.getResponse(), "Missing or invalid Authorization header");
        }

        String token = authHeader.substring(BEARER_PREFIX.length());
        return authValidationClient.validate(token)
                .flatMap(validationResponse -> continueIfValid(exchange, chain, validationResponse))
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return unauthorized(exchange.getResponse(), "Unauthorized");
                    } else if (ex.getStatusCode() == HttpStatus.FORBIDDEN) {
                        return forbidden(exchange.getResponse(), "Forbidden");
                    }
                    return gatewayError(exchange.getResponse(), "Auth service error");
                })
                .onErrorResume(ex -> gatewayError(exchange.getResponse(), "Auth service unavailable"));
    }

    private boolean isPublicRequest(ServerHttpRequest request) {
        String path = request.getURI().getPath();
        return request.getMethod() == HttpMethod.OPTIONS || PUBLIC_PATHS.contains(path);
    }

    private Mono<Void> continueIfValid(
            ServerWebExchange exchange,
            GatewayFilterChain chain,
            TokenValidationResponse validationResponse
    ) {
        if (validationResponse == null || !validationResponse.valid()) {
            return unauthorized(exchange.getResponse(), "Token is invalid");
        }

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove(USER_ID_HEADER);
                    headers.remove(USER_ROLE_HEADER);
                    headers.remove(SERVICE_NAME_HEADER);
                    headers.add(USER_ID_HEADER, String.valueOf(validationResponse.userId()));
                    headers.add(USER_ROLE_HEADER, String.valueOf(validationResponse.role()));
                })
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private Mono<Void> forbidden(ServerHttpResponse response, String message) {
        return writeError(response, HttpStatus.FORBIDDEN, message);
    }

    private Mono<Void> gatewayError(ServerHttpResponse response, String message) {
        return writeError(response, HttpStatus.BAD_GATEWAY, message);
    }

    private Mono<Void> unauthorized(ServerHttpResponse response, String message) {
        return writeError(response, HttpStatus.UNAUTHORIZED, message);
    }

    private Mono<Void> writeError(ServerHttpResponse response, HttpStatus status, String message) {
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String body = String.format("{\"status\":%s,\"message\":\"%s\"}", status.value(), message);
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
