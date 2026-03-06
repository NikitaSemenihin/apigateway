package com.innowise.apigateway.dto;

public record TokenValidationResponse(
        boolean valid,
        Long userId,
        String role
) {
}
