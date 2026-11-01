package com.autoforge.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
public class HealthController {
    private final DataSource dataSource;

    @GetMapping({"/health", "/api/v1/health"})
    public ResponseEntity<Map<String, String>> healthCheck() {
        Map<String, String> response = new LinkedHashMap<>();

        boolean dbConnected;
        try (Connection conn = dataSource.getConnection()) {
            dbConnected = conn.isValid(2);
        } catch (SQLException e) {
            log.warn("Database health check failed: {}", e.getMessage());
            dbConnected = false;
        }

        response.put("database", dbConnected ? "connected" : "disconnected");
        response.put("status", dbConnected ? "ok" : "error");
        return ResponseEntity.status(dbConnected ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
}
