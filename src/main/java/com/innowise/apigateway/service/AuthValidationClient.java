package com.innowise.apigateway.service;

import com.innowise.apigateway.dto.TokenValidationRequest;
import com.innowise.apigateway.dto.TokenValidationResponse;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
public class AuthValidationClient {

    private final WebClient authWebClient;

    public AuthValidationClient(WebClient authWebClient) {
        this.authWebClient = authWebClient;
    }

    public Mono<TokenValidationResponse> validate(String token) {
        return authWebClient.post()
                .uri("/api/auth/validate")
                .bodyValue(new TokenValidationRequest(token))
                .retrieve()
                .onStatus(HttpStatusCode::isError, response ->
                        response.createException().flatMap(Mono::error))
                .bodyToMono(TokenValidationResponse.class);
    }
}
