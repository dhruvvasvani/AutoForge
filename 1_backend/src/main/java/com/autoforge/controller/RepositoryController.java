package com.autoforge.controller;

// Week 9 deliverable: Repository APIs.
import com.autoforge.dto.ConnectRepositoryRequest;
import com.autoforge.dto.RepositoryResponse;
import com.autoforge.dto.ScanResponse;
import com.autoforge.dto.ScanProgressResponse;
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

    @GetMapping("/{id}/scans")
    public ResponseEntity<List<ScanProgressResponse>> scans(
            Authentication authentication,
            @PathVariable Long id
    ) {
        return ResponseEntity.ok(repositoryService.getRepositoryScanProgress(id, authentication.getName()));
    }

    @PostMapping("/{id}/trigger-scan")
    public ResponseEntity<ScanResponse> triggerScan(
            Authentication authentication,
            @PathVariable Long id
    ) {
        var scan = repositoryService.triggerRepositoryScan(authentication.getName(), id);
        return ResponseEntity.accepted().body(
                new ScanResponse(scan.getId(), scan.getStatus().name(), scan.getCommitSha())
        );
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(Authentication authentication, @PathVariable Long id) {
        repositoryService.deleteRepository(authentication.getName(), id);
        return ResponseEntity.noContent().build();
    }
}
