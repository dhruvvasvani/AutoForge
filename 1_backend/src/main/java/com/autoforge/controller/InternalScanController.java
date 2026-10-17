package com.autoforge.controller;

// Week 9 deliverable: internal API used only by 2_pipeline (never the browser)
// to create scan rows and post back merged scanner results.
// SECURITY NOTE: currently open like /api/webhooks/**; before Demo 2, gate
// this behind a shared internal secret header (same pattern as the GitHub
// webhook signature) so only 2_pipeline can call it.
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
        Scan scan = scanService.createScanJobFromPush(request.getRepoFullName(), request.getCommitSha(), "push");
        return ResponseEntity.ok(new ScanResponse(scan.getId(), scan.getStatus().name(), scan.getCommitSha()));
    }

    @PostMapping("/{id}/results")
    public ResponseEntity<ScanResponse> submitResults(@PathVariable Long id,
                                                       @RequestBody ScanResultsPayload payload) {
        Scan scan = scanService.persistScanResults(id, payload.getSemgrep(), payload.getCheckov());
        return ResponseEntity.ok(new ScanResponse(scan.getId(), scan.getStatus().name(), scan.getCommitSha()));
    }
}
