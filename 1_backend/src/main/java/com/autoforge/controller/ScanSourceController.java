package com.autoforge.controller;

import com.autoforge.dto.ScanSourceImportRequest;
import com.autoforge.dto.ScanSourceUploadResponse;
import com.autoforge.service.ScanSourceService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/scans")
@RequiredArgsConstructor
public class ScanSourceController {
    private final ScanSourceService scanSourceService;

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ScanSourceUploadResponse> uploadSource(
            @RequestPart("file") MultipartFile file,
            @RequestParam("projectName") String projectName,
            @RequestParam(name = "branch", required = false) String branch,
            Authentication authentication
    ) throws IOException {
        ScanSourceUploadResponse response = scanSourceService.uploadZip(
                file, projectName, branch, authentication.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/import-path")
    public ResponseEntity<ScanSourceUploadResponse> importSourcePath(
            @Valid @RequestBody ScanSourceImportRequest request,
            Authentication authentication
    ) throws IOException {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(scanSourceService.importDirectory(request, authentication.getName()));
    }
}
