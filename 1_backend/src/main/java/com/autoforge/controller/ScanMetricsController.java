package com.autoforge.controller;

import com.autoforge.dto.ScanMetricsRequest;
import com.autoforge.dto.ScanMetricsResponse;
import com.autoforge.service.ScanMetricsService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scan-metrics")
@RequiredArgsConstructor
public class ScanMetricsController {

    private final ScanMetricsService scanMetricsService;

    @PostMapping
    public ResponseEntity<ScanMetricsResponse> record(
            Authentication authentication,
            @Valid @RequestBody ScanMetricsRequest request
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(scanMetricsService.record(authentication.getName(), request));
    }

    @GetMapping
    public Map<String, Object> history(
            Authentication authentication,
            @RequestParam(defaultValue = "30") int limit
    ) {
        List<ScanMetricsResponse> scans = scanMetricsService.history(authentication.getName(), limit);
        return Map.of("scans", scans, "count", scans.size());
    }
}
