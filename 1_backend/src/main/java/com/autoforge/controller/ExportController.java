package com.autoforge.controller;

import com.autoforge.service.SarifService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/scans")
@RequiredArgsConstructor
public class ExportController {
    private final SarifService sarifService;

    @GetMapping("/{scanId}/export/sarif")
    public ResponseEntity<Map<String, Object>> exportSarif(@PathVariable("scanId") Long scanId) {
        Map<String, Object> sarifReport = sarifService.generateSarifReport(scanId);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"scan-" + scanId + ".sarif\"")
                .contentType(MediaType.APPLICATION_JSON)
                .body(sarifReport);
    }
}
