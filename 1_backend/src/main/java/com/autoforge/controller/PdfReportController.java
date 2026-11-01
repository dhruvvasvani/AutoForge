package com.autoforge.controller;

import com.autoforge.service.PdfReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reports")
@RequiredArgsConstructor
public class PdfReportController {
    private final PdfReportService pdfReportService;

    @GetMapping("/pdf/{scanId}")
    public ResponseEntity<byte[]> downloadPdf(@PathVariable Long scanId, Authentication authentication) {
        byte[] report = pdfReportService.generate(scanId, authentication.getName());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"scan-" + scanId + ".pdf\"")
                .body(report);
    }
}
