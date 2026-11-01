package com.autoforge.controller;

import com.autoforge.dto.PolicyEvaluationRequest;
import com.autoforge.dto.PolicyEvaluationResponse;
import com.autoforge.service.PolicyEngine;
import com.autoforge.service.GitHubQualityGatePublisher;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/policies")
@RequiredArgsConstructor
public class PolicyEvaluationController {
    private final PolicyEngine policyEngine;
    private final GitHubQualityGatePublisher qualityGatePublisher;

    @PostMapping("/evaluate")
    public ResponseEntity<PolicyEvaluationResponse> evaluatePolicy(@Valid @RequestBody PolicyEvaluationRequest request) {
        return ResponseEntity.ok(policyEngine.evaluate(request));
    }

    @PostMapping("/evaluate/github-status")
    public ResponseEntity<PolicyEvaluationResponse> evaluateAndPublishGitHubStatus(
            @Valid @RequestBody PolicyEvaluationRequest request,
            Authentication authentication
    ) {
        PolicyEvaluationResponse result = policyEngine.evaluate(request);
        qualityGatePublisher.publish(request.getScanId(), authentication.getName(),
                result.isPassed(), result.getReason());
        return ResponseEntity.ok(result);
    }
}
