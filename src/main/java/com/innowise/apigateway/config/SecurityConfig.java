package com.innowise.apigateway.config;

import com.innowise.apigateway.security.JsonServerAccessDeniedHandler;
import com.innowise.apigateway.security.JsonServerAuthenticationEntryPoint;
import com.innowise.apigateway.security.JwtServerAuthenticationConverter;
import com.innowise.apigateway.security.SecurityPaths;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            ReactiveAuthenticationManager jwtAuthenticationManager,
            ServerAuthenticationConverter jwtAuthenticationConverter
    ) {
        AuthenticationWebFilter jwtAuthenticationFilter = new AuthenticationWebFilter(jwtAuthenticationManager);
        jwtAuthenticationFilter.setServerAuthenticationConverter(jwtAuthenticationConverter);
        jwtAuthenticationFilter.setSecurityContextRepository(NoOpServerSecurityContextRepository.getInstance());

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new JsonServerAuthenticationEntryPoint())
                        .accessDeniedHandler(new JsonServerAccessDeniedHandler()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        .pathMatchers(SecurityPaths.PUBLIC_PATHS_MATCHERS).permitAll()
                        .anyExchange().authenticated())
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public ServerAuthenticationConverter jwtAuthenticationConverter() {
        return new JwtServerAuthenticationConverter();
    }
}