package com.autoforge;

import com.autoforge.config.WebCorsConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;

import static org.junit.jupiter.api.Assertions.*;

class WebCorsConfigurationTest {
    @Test
    void allowsOnlyConfiguredFrontendOriginsAndBearerHeaders() {
        var source = new WebCorsConfiguration()
                .corsConfigurationSource("https://ui.example,http://localhost:5173");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/v1/scans");
        CorsConfiguration config = source.getCorsConfiguration(request);

        assertNotNull(config);
        assertEquals("https://ui.example", config.checkOrigin("https://ui.example"));
        assertNull(config.checkOrigin("https://attacker.example"));
        assertTrue(config.checkHeaders(java.util.List.of("authorization", "content-type")).size() > 0);
        assertFalse(config.getAllowCredentials());
    }

    @Test
    void refusesWildcardAndEmptyOriginLists() {
        var cors = new WebCorsConfiguration();
        assertThrows(IllegalStateException.class, () -> cors.corsConfigurationSource("*"));
        assertThrows(IllegalStateException.class, () -> cors.corsConfigurationSource(" , "));
    }
}
