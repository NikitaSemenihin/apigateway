package com.innowise.apigateway.security;

import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.Arrays;
import java.util.stream.Stream;

public final class SecurityPaths {

    private static final String[] PUBLIC_PATHS = {
            "/api/auth/login",
            "/api/auth/register"
    };

    public static final String[] PUBLIC_PATHS_MATCHERS = Arrays.stream(PUBLIC_PATHS)
            .flatMap(SecurityPaths::expandMatcherVariants)
            .distinct()
            .toArray(String[]::new);

    private static Stream<String> expandMatcherVariants(String path) {
        String normalizedPath = normalizePath(path);
        return "/".equals(normalizedPath)
                ? Stream.of(normalizedPath)
                : Stream.of(normalizedPath, normalizedPath + "/");
    }

    private SecurityPaths() {
    }

    public static boolean isPublic(ServerHttpRequest request) {
        if (request.getMethod() == HttpMethod.OPTIONS) {
            return true;
        }

        String path = normalizePath(request.getURI().getPath());

        for (String publicPath : PUBLIC_PATHS) {
            if (normalizePath(publicPath).equals(path)) {
                return true;
            }
        }
        return false;
    }

    private static String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }

        int end = path.length();
        while (end > 1 && path.charAt(end - 1) == '/') {
            end--;
        }
        return path.substring(0,end);
    }
}
