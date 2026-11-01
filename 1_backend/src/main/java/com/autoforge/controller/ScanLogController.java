package com.autoforge.controller;

import com.autoforge.config.ScanWebSocketHandler;
import com.autoforge.dto.WorkerLogRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/scans")
@RequiredArgsConstructor
@Slf4j
public class ScanLogController {
    private final ScanWebSocketHandler scanWebSocketHandler;

    @PostMapping("/{jobId}/logs")
    public ResponseEntity<Map<String, Object>> receiveWorkerLogs(
            @PathVariable("jobId") Long jobId,
            @RequestBody WorkerLogRequest logRequest
    ) {
        logRequest.setJobId(jobId);
        scanWebSocketHandler.broadcast(jobId, logRequest);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "broadcasted");
        response.put("job_id", jobId);
        return ResponseEntity.ok(response);
    }
}
