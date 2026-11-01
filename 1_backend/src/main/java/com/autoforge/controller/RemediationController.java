package com.autoforge.controller;

import com.autoforge.dto.PullRequestResponseDto;
import com.autoforge.dto.RemediationGenerateResponse;
import com.autoforge.dto.RemediationPreviewResponse;
import com.autoforge.entity.Fix;
import com.autoforge.service.PullRequestService;
import com.autoforge.service.RemediationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class RemediationController {
    private final RemediationService remediationService;
    private final PullRequestService pullRequestService;

    @PostMapping("/api/v1/findings/{findingId}/remediation/preview")
    public ResponseEntity<RemediationPreviewResponse> previewRemediation(
            @PathVariable("findingId") Long findingId, Authentication authentication
    ) {
        return ResponseEntity.ok(remediationService.preview(findingId, authentication.getName()));
    }

    @PostMapping("/api/v1/findings/{findingId}/remediation/generate")
    public ResponseEntity<RemediationGenerateResponse> generateRemediation(
            @PathVariable("findingId") Long findingId, Authentication authentication
    ) {
        RemediationGenerateResponse response = remediationService.generate(findingId, authentication.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/api/v1/fix/generate")
    public ResponseEntity<RemediationGenerateResponse> generateFix(
            @RequestParam("findingId") Long findingId, Authentication authentication
    ) {
        RemediationGenerateResponse response = remediationService.generate(findingId, authentication.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping(value = "/api/v1/remediations/{id}/patch", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> getRemediationPatch(@PathVariable("id") Long id, Authentication authentication) {
        String patch = remediationService.getPatch(id, authentication.getName());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"fix-" + id + ".patch\"")
                .body(patch);
    }

    @PostMapping("/api/v1/remediations/{id}/create-pr")
    public ResponseEntity<PullRequestResponseDto> createPullRequest(
            @PathVariable("id") Long id, Authentication authentication
    ) {
        PullRequestResponseDto response = pullRequestService.createPullRequest(id, authentication.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/api/v1/remediations/{id}/approve")
    public ResponseEntity<Map<String, Object>> approveFix(@PathVariable("id") Long id, Authentication authentication) {
        Fix fix = remediationService.approveFix(id, authentication.getName());
        return ResponseEntity.ok(Map.of(
                "id", fix.getId(),
                "status", fix.getStatus(),
                "message", "Fix approved successfully"
        ));
    }

    @PostMapping("/api/v1/remediations/{id}/reject")
    public ResponseEntity<Map<String, Object>> rejectFix(@PathVariable("id") Long id, Authentication authentication) {
        Fix fix = remediationService.rejectFix(id, authentication.getName());
        return ResponseEntity.ok(Map.of(
                "id", fix.getId(),
                "status", fix.getStatus(),
                "message", "Fix rejected"
        ));
    }
}
