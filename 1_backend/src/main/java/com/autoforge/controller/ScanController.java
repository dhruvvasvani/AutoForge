package com.autoforge.controller;

import com.autoforge.dto.ScanJobResponse;
import com.autoforge.dto.ScanRunRequest;
import com.autoforge.dto.ScanStatusUpdateRequest;
import com.autoforge.dto.ScanTriggerRequest;
import com.autoforge.service.ScanExecutionService;
import com.autoforge.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class ScanController {
    private final ScanService scanService;
    private final ScanExecutionService scanExecutionService;

    @PostMapping("/api/v1/scans/trigger")
    public ResponseEntity<ScanJobResponse> triggerScan(@Valid @RequestBody ScanTriggerRequest request) {
        ScanJobResponse response = scanService.triggerScan(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/api/v1/scans/run")
    public ResponseEntity<ScanJobResponse> runScan(
            @Valid @RequestBody ScanRunRequest request,
            Authentication authentication
    ) throws java.io.IOException {
        return ResponseEntity.accepted().body(scanExecutionService.startScan(request.getScanId(), authentication.getName()));
    }

    @GetMapping("/api/v1/scans")
    public ResponseEntity<List<ScanJobResponse>> listScans(
            @RequestParam(name = "skip", defaultValue = "0") int skip,
            @RequestParam(name = "limit", defaultValue = "10") int limit,
            Authentication authentication
    ) {
        return ResponseEntity.ok(scanService.listScans(skip, limit, authentication.getName()));
    }

    @GetMapping("/api/v1/scans/{jobId}")
    public ResponseEntity<ScanJobResponse> getScanJob(@PathVariable("jobId") Long jobId) {
        return ResponseEntity.ok(scanService.getScanJob(jobId));
    }

    @GetMapping("/api/v1/projects/{projectId}/scans")
    public ResponseEntity<List<ScanJobResponse>> listProjectScans(
            @PathVariable("projectId") Long projectId,
            @RequestParam(name = "skip", defaultValue = "0") int skip,
            @RequestParam(name = "limit", defaultValue = "10") int limit,
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size
    ) {
        if (page != null && size != null) {
            skip = page * size;
            limit = size;
        }
        return ResponseEntity.ok(scanService.listScansForProject(projectId, skip, limit));
    }

    @PatchMapping("/api/v1/scans/{jobId}/status")
    public ResponseEntity<ScanJobResponse> updateScanStatus(
            @PathVariable("jobId") Long jobId,
            @RequestBody ScanStatusUpdateRequest request
    ) {
        return ResponseEntity.ok(scanService.updateScanStatus(jobId, request.getStatus(), request.getErrorMessage()));
    }

    @GetMapping("/api/v1/scans/{scanId}/results")
    public ResponseEntity<com.autoforge.dto.ScanDetailResultResponse> getScanResults(@PathVariable("scanId") Long scanId) {
        return ResponseEntity.ok(scanService.getScanResults(scanId));
    }

    @GetMapping("/api/v1/scans/{scanId}/ml-predictions")
    public ResponseEntity<List<com.autoforge.dto.MLPredictionResponseDto>> getScanMLPredictions(@PathVariable("scanId") Long scanId) {
        return ResponseEntity.ok(scanService.getScanMLPredictions(scanId));
    }
}
