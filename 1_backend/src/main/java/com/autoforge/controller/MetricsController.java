package com.autoforge.controller;

import com.autoforge.dto.ProjectMetricsResponse;
import com.autoforge.dto.ScanMetricsResponse;
import com.autoforge.service.MetricsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MetricsController {
    private final MetricsService metricsService;

    private final com.autoforge.service.DashboardService dashboardService;

    @GetMapping("/api/v1/scans/{scanId}/metrics")
    public ResponseEntity<ScanMetricsResponse> getScanMetrics(@PathVariable("scanId") Long scanId) {
        return ResponseEntity.ok(metricsService.getScanMetrics(scanId));
    }

    @GetMapping("/api/v1/projects/{projectId}/metrics")
    public ResponseEntity<ProjectMetricsResponse> getProjectMetrics(@PathVariable("projectId") Long projectId) {
        return ResponseEntity.ok(metricsService.getProjectMetrics(projectId));
    }

    @GetMapping("/api/v1/projects/{projectId}/metrics/history")
    public ResponseEntity<java.util.List<ScanMetricsResponse>> getProjectMetricsHistory(@PathVariable("projectId") Long projectId) {
        return ResponseEntity.ok(dashboardService.getProjectMetricsHistory(projectId));
    }
}
