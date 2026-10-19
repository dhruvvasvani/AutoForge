package com.autoforge.controller;

// Internal API for the pipeline to create scan rows and post merged results.
import com.autoforge.dto.CreateScanRequest;
import com.autoforge.dto.ScanResponse;
import com.autoforge.dto.ScanResultsPayload;
import com.autoforge.entity.Scan;
import com.autoforge.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/internal/scans")
@RequiredArgsConstructor
public class InternalScanController {

    private final ScanService scanService;

    @PostMapping
    public ResponseEntity<ScanResponse> create(@Valid @RequestBody CreateScanRequest request) {
        Scan scan = scanService.createScanJobFromPush(
                request.getRepoFullName(), request.getCommitSha(),
                request.getEventType() == null || request.getEventType().isBlank()
                        ? "push" : request.getEventType());
        return ResponseEntity.ok(new ScanResponse(scan.getId(), scan.getStatus().name(), scan.getCommitSha()));
    }

    @PostMapping("/{id}/results")
    public ResponseEntity<ScanResponse> submitResults(@PathVariable Long id,
                                                       @RequestBody ScanResultsPayload payload) {
        Scan scan = scanService.persistScanResults(
                id, payload.getSemgrep(), payload.getCheckov(), payload.getAst(),
                payload.getCombinedRiskScore());
        return ResponseEntity.ok(new ScanResponse(scan.getId(), scan.getStatus().name(), scan.getCommitSha()));
    }
}
