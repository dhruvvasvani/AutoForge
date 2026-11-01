package com.autoforge.controller;

import com.autoforge.dto.CallTraceStepDto;
import com.autoforge.dto.FindingResponseDto;
import com.autoforge.service.FindingService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class FindingController {
    private final FindingService findingService;

    @GetMapping("/api/v1/scans/{scanId}/findings")
    public ResponseEntity<List<FindingResponseDto>> getScanFindings(@PathVariable("scanId") Long scanId) {
        return ResponseEntity.ok(findingService.getFindingsByScan(scanId));
    }

    @GetMapping("/api/v1/projects/{projectId}/findings")
    public ResponseEntity<List<FindingResponseDto>> getProjectFindings(
            @PathVariable("projectId") Long projectId,
            @RequestParam(name = "severity", required = false) String severity,
            @RequestParam(name = "rule_id", required = false) String ruleId,
            @RequestParam(name = "skip", defaultValue = "0") int skip,
            @RequestParam(name = "limit", defaultValue = "10") int limit,
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size
    ) {
        if (page != null && size != null) {
            skip = page * size;
            limit = size;
        }
        return ResponseEntity.ok(findingService.getFindingsByProject(projectId, severity, ruleId, skip, limit));
    }

    @GetMapping("/api/v1/findings/{findingId}/traces")
    public ResponseEntity<List<CallTraceStepDto>> getFindingTraces(@PathVariable("findingId") Long findingId) {
        return ResponseEntity.ok(findingService.getCallTracesByFinding(findingId));
    }
}
