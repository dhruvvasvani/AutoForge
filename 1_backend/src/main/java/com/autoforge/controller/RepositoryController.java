package com.autoforge.controller;

import com.autoforge.dto.ConnectRepositoryRequest;
import com.autoforge.dto.RepositoryResponse;
import com.autoforge.dto.ScanJobResponse;
import com.autoforge.service.RepositoryScanService;
import com.autoforge.service.RepositoryService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/repositories")
@RequiredArgsConstructor
public class RepositoryController {
    private final RepositoryService repositoryService;
    private final RepositoryScanService repositoryScanService;

    @PostMapping
    public ResponseEntity<RepositoryResponse> connect(Authentication authentication,
                                                       @Valid @RequestBody ConnectRepositoryRequest request) {
        return ResponseEntity.ok(
                repositoryService.connectRepository(authentication.getName(), request.getGithubRepoFullName()));
    }

    @GetMapping
    public ResponseEntity<List<RepositoryResponse>> list(Authentication authentication) {
        return ResponseEntity.ok(repositoryService.listRepositories(authentication.getName()));
    }

    @PostMapping("/{id}/trigger-scan")
    public ResponseEntity<ScanJobResponse> triggerScan(Authentication authentication, @PathVariable Long id) {
        return ResponseEntity.accepted()
                .body(repositoryScanService.triggerLatestScan(id, authentication.getName()));
    }

    @GetMapping("/{id}/scans")
    public ResponseEntity<List<ScanJobResponse>> listScans(Authentication authentication, @PathVariable Long id) {
        return ResponseEntity.ok(repositoryScanService.listScans(id, authentication.getName()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(Authentication authentication, @PathVariable Long id) {
        repositoryService.deleteRepository(authentication.getName(), id);
        return ResponseEntity.noContent().build();
    }
}
