package com.autoforge.controller;

import com.autoforge.dto.DashboardSummaryResponse;
import com.autoforge.dto.FindingResponseDto;
import com.autoforge.dto.ScanJobResponse;
import com.autoforge.service.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class DashboardController {
    private final DashboardService dashboardService;

    @GetMapping("/dashboard")
    public org.springframework.web.servlet.view.RedirectView getDashboardView() {
        return new org.springframework.web.servlet.view.RedirectView("/index.html");
    }

    @GetMapping({"/dashboard/summary", "/api/v1/dashboard/summary"})
    public ResponseEntity<DashboardSummaryResponse> getSummary() {
        return ResponseEntity.ok(dashboardService.getSummary());
    }

    @GetMapping({"/dashboard/recent-scans", "/api/v1/dashboard/recent-scans"})
    public ResponseEntity<List<ScanJobResponse>> getRecentScans(
            @RequestParam(name = "limit", defaultValue = "10") int limit
    ) {
        return ResponseEntity.ok(dashboardService.getRecentScans(limit));
    }

    @GetMapping({"/dashboard/top-findings", "/api/v1/dashboard/top-findings"})
    public ResponseEntity<List<FindingResponseDto>> getTopFindings(
            @RequestParam(name = "limit", defaultValue = "10") int limit
    ) {
        return ResponseEntity.ok(dashboardService.getTopFindings(limit));
    }
}
