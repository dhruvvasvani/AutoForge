package com.autoforge.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Component
public class InternalApiTokenFilter extends OncePerRequestFilter {

    private final String configuredToken;

    public InternalApiTokenFilter(@Value("${autoforge.internal-token:}") String configuredToken) {
        this.configuredToken = configuredToken;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().startsWith("/api/internal/");
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String receivedToken = request.getHeader("X-AutoForge-Internal-Token");
        if (configuredToken.isBlank() || receivedToken == null
                || !MessageDigest.isEqual(configuredToken.getBytes(StandardCharsets.UTF_8),
                receivedToken.getBytes(StandardCharsets.UTF_8))) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid internal API token");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
