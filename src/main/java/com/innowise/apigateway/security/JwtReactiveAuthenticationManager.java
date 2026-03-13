package com.innowise.apigateway.security;

import com.innowise.apigateway.dto.TokenValidationResponse;
import com.innowise.apigateway.service.AuthValidationClient;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    private final AuthValidationClient authValidationClient;

    public JwtReactiveAuthenticationManager(AuthValidationClient authValidationClient) {
        this.authValidationClient = authValidationClient;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String token = String.valueOf(authentication.getCredentials());
        return authValidationClient.validate(token)
                .switchIfEmpty(Mono.error(new BadCredentialsException("Token validation failed")))
                .flatMap(this::toAuthentication)
                .onErrorMap(WebClientResponseException.class, this::mapValidationError);
    }

    private Mono<Authentication> toAuthentication(TokenValidationResponse response) {
        if (response == null || !response.valid() || response.userId() == null || response.role() == null) {
            return Mono.error(new BadCredentialsException("Token is invalid"));
        }

        AuthenticatedUser principal = new AuthenticatedUser(response.userId(), response.role());
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + response.role());
        Authentication authenticated = UsernamePasswordAuthenticationToken.authenticated(
                principal,
                null,
                List.of(authority)
        );
        return Mono.just(authenticated);
    }

    private RuntimeException mapValidationError(WebClientResponseException exception) {
        if (exception.getStatusCode() == HttpStatus.UNAUTHORIZED || exception.getStatusCode() == HttpStatus.FORBIDDEN) {
            return new BadCredentialsException("Token is invalid", exception);
        }
        return new UsernameNotFoundException("Auth service is unavailable", exception);
    }
}
