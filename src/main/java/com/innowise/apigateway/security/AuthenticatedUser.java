package com.innowise.apigateway.security;

public record AuthenticatedUser(
        Long userId,
        String role
) {
}
