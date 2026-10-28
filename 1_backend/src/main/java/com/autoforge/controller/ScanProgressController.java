package com.autoforge.controller;

import com.autoforge.dto.ScanFindingResponse;
import com.autoforge.dto.ScanProgressResponse;
import com.autoforge.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/scans")
@RequiredArgsConstructor
public class ScanProgressController {

    private final ScanService scanService;

    @GetMapping("/{id}/status")
    public ResponseEntity<ScanProgressResponse> status(
            Authentication authentication,
            @PathVariable Long id
    ) {
        return ResponseEntity.ok(scanService.getScanProgress(id, authentication.getName()));
    }

    @GetMapping("/{id}/findings")
    public ResponseEntity<List<ScanFindingResponse>> findings(
            Authentication authentication,
            @PathVariable Long id
    ) {
        return ResponseEntity.ok(scanService.getScanFindings(id, authentication.getName()));
    }
}
