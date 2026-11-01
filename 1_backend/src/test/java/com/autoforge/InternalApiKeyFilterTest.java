package com.autoforge;

import com.autoforge.security.InternalApiKeyFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InternalApiKeyFilterTest {
    private final InternalApiKeyFilter filter = new InternalApiKeyFilter("test-secret-key");

    @Test
    void nonInternalPathBypassesFilter() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/plans");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);
        assertEquals(200, response.getStatus());
    }

    @Test
    void internalPathWithoutKeyReturns401() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/internal/scans");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);
        assertEquals(401, response.getStatus());
    }

    @Test
    void internalPathWithWrongKeyReturns401() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/internal/scans");
        request.addHeader("X-Internal-Api-Key", "wrong-secret");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);
        assertEquals(401, response.getStatus());
    }

    @Test
    void internalPathWithValidKeyPasses() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/internal/scans");
        request.addHeader("X-Internal-Api-Key", "test-secret-key");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);
        assertEquals(200, response.getStatus());
    }
}
