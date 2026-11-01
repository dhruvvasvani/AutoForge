package com.autoforge.service;

import com.autoforge.dto.PolicyEvaluationRequest;
import com.autoforge.dto.PolicyEvaluationResponse;
import com.autoforge.entity.Finding;
import com.autoforge.entity.Policy;
import com.autoforge.entity.Scan;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.PolicyRepository;
import com.autoforge.repository.ScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class PolicyEngine {
    private final FindingRepository findingRepository;
    private final ScanRepository scanRepository;
    private final PolicyRepository policyRepository;

    public PolicyEvaluationResponse evaluate(PolicyEvaluationRequest request) {
        Scan scan = scanRepository.findById(request.getScanId())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + request.getScanId()));

        Policy policy = scan.getProject() == null ? null
                : policyRepository.findByProjectId(scan.getProject().getId()).orElse(null);
        int maxCritical = request.getMaxCritical() != null ? request.getMaxCritical()
                : policy != null ? policy.getMaxCritical() : 0;
        int maxHigh = request.getMaxHigh() != null ? request.getMaxHigh()
                : policy != null ? policy.getMaxHigh() : 2;

        List<Finding> findings = findingRepository.findByScanId(request.getScanId());

        int criticalCount = 0;
        int highCount = 0;
        for (Finding f : findings) {
            if (!isReachableForGate(f)) {
                continue;
            }
            String sev = f.getSeverity() != null ? f.getSeverity().toUpperCase() : "MEDIUM";
            if ("CRITICAL".equals(sev)) {
                criticalCount++;
            } else if ("HIGH".equals(sev)) {
                highCount++;
            }
        }

        boolean passed = (criticalCount <= maxCritical) && (highCount <= maxHigh);
        String reason = String.format("Found %d reachable CRITICAL and %d reachable HIGH vulnerabilities.",
                criticalCount, highCount);

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("critical_count", criticalCount);
        metrics.put("high_count", highCount);
        metrics.put("unreachable_findings_excluded", findings.stream().filter(f -> !isReachableForGate(f)).count());
        metrics.put("max_critical", maxCritical);
        metrics.put("max_high", maxHigh);

        return PolicyEvaluationResponse.builder()
                .passed(passed)
                .status(passed ? "PASS" : "FAIL")
                .reason(reason)
                .metrics(metrics)
                .build();
    }

    private boolean isReachableForGate(Finding finding) {
        if (finding.getReachabilityStatus() != null && !finding.getReachabilityStatus().isBlank()) {
            String status = finding.getReachabilityStatus().trim().toUpperCase();
            return !List.of("UNREACHABLE", "UNREACHABLE_NOISE", "FALSE_POSITIVE", "NOT_REACHABLE").contains(status);
        }
        return !Boolean.FALSE.equals(finding.getIsReachable());
    }

    public com.autoforge.dto.ProjectPolicyDto getProjectPolicy(Long projectId) {
        Policy policy = policyRepository.findByProjectId(projectId).orElse(null);
        int maxCrit = policy != null ? policy.getMaxCritical() : 0;
        int maxHigh = policy != null ? policy.getMaxHigh() : 2;
        java.time.Instant updated = policy != null ? policy.getUpdatedAt() : java.time.Instant.now();

        return com.autoforge.dto.ProjectPolicyDto.builder()
                .projectId(projectId)
                .maxCritical(maxCrit)
                .maxHigh(maxHigh)
                .updatedAt(updated)
                .build();
    }

    @Transactional
    public com.autoforge.dto.ProjectPolicyDto updateProjectPolicy(Long projectId, com.autoforge.dto.ProjectPolicyDto dto) {
        Policy policy = policyRepository.findByProjectId(projectId).orElseGet(() -> {
            Policy p = new Policy();
            p.setProject(new com.autoforge.entity.Project());
            p.getProject().setId(projectId);
            return p;
        });

        if (dto.getMaxCritical() != null) policy.setMaxCritical(dto.getMaxCritical());
        if (dto.getMaxHigh() != null) policy.setMaxHigh(dto.getMaxHigh());
        policy.setUpdatedAt(java.time.Instant.now());

        Policy saved = policyRepository.save(policy);
        return com.autoforge.dto.ProjectPolicyDto.builder()
                .projectId(projectId)
                .maxCritical(saved.getMaxCritical())
                .maxHigh(saved.getMaxHigh())
                .updatedAt(saved.getUpdatedAt())
                .build();
    }
}
