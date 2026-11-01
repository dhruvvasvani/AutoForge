package com.autoforge.controller;

import com.autoforge.dto.HybridScanPayload;
import com.autoforge.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/results")
@RequiredArgsConstructor
@Slf4j
public class ResultSubmissionController {
    private final ScanService scanService;

    @PostMapping("/submit")
    public ResponseEntity<Map<String, Object>> submitResults(@Valid @RequestBody HybridScanPayload payload) {
        log.info("Received hybrid AST + ML results for scan job {}", payload.getJobId());
        scanService.persistHybridScanResults(payload);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "success");
        response.put("message", "Scan findings and ML scores persisted successfully");
        response.put("job_id", payload.getJobId());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
