package com.autoforge.service;

import com.autoforge.dto.RemediationGenerateResponse;
import com.autoforge.dto.RemediationPreviewResponse;
import com.autoforge.entity.Finding;
import com.autoforge.entity.Fix;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.FixRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class RemediationService {
    private final FindingRepository findingRepository;
    private final FixRepository fixRepository;
    private final AuditLogService auditLogService;
    private final LlmRemediationClient llmRemediationClient;

    @Transactional(readOnly = true)
    public RemediationPreviewResponse preview(Long findingId, String userEmail) {
        Finding finding = ownedFinding(findingId, userEmail);

        String originalSnippet = finding.getCodeSnippet() != null ? finding.getCodeSnippet() : "";
        String diff = llmRemediationClient.generatePatch(finding);

        return RemediationPreviewResponse.builder()
                .findingId(finding.getId())
                .filePath(finding.getFilePath())
                .lineNumber(finding.getLineNumber())
                .originalSnippet(originalSnippet)
                .suggestedFix(diff)
                .unifiedDiff(diff)
                .build();
    }

    public RemediationGenerateResponse generate(Long findingId, String userEmail) {
        Finding finding = ownedFinding(findingId, userEmail);

        String diff = llmRemediationClient.generatePatch(finding);

        Fix fix = new Fix();
        fix.setFinding(finding);
        fix.setFilePath(finding.getFilePath());
        fix.setSuggestedPatch(diff);
        fix.setModelUsed(llmRemediationClient.getConfiguredModel());
        fix.setStatus("GENERATED");
        fix.setValidated(false);

        Fix saved = fixRepository.save(fix);
        auditLogService.log("FIX_GENERATED", "Automated remediation patch generated for finding ID " + findingId);
        log.info("Generated and saved automated fix {} for finding {}", saved.getId(), findingId);

        return RemediationGenerateResponse.builder()
                .id(saved.getId())
                .findingId(finding.getId())
                .status(saved.getStatus())
                .modelUsed(saved.getModelUsed())
                .patch(saved.getSuggestedPatch())
                .createdAt(saved.getCreatedAt())
                .build();
    }

    /**
     * Generate and persist a fix during scan ingestion.
     * Only confirmed reachable P0/P1 findings are eligible.
     */
    public boolean generateAutomatically(Finding finding) {
        if (finding == null) return false;

        String priority = finding.getPriority();
        if (priority == null ||
                !java.util.Set.of("P0", "P1").contains(priority.toUpperCase())) {
            return false;
        }

        if (!Boolean.TRUE.equals(finding.getIsReachable())) return false;
        if (finding.getCodeSnippet() == null || finding.getCodeSnippet().isBlank()) return false;

        if (fixRepository.findTopByFindingIdOrderByCreatedAtDesc(finding.getId()).isPresent()) {
            log.info("Skipping duplicate automatic fix for finding {}", finding.getId());
            return false;
        }

        final String patch;
        try {
            patch = llmRemediationClient.generatePatch(finding);
        } catch (Exception ex) {
            // Keep provider failures from escaping the transactional service method.
            log.warn("AI patch generation failed for finding {}: {}",
                    finding.getId(), ex.getMessage());
            return false;
        }

        Fix fix = new Fix();
        fix.setFinding(finding);
        fix.setFilePath(finding.getFilePath());
        fix.setSuggestedPatch(patch);
        fix.setModelUsed(llmRemediationClient.getConfiguredModel());
        fix.setStatus("GENERATED");
        fix.setValidated(false);

        Fix saved = fixRepository.save(fix);
        log.info("Automatically generated fix {} for finding {}", saved.getId(), finding.getId());
        return true;
    }

    @Transactional(readOnly = true)
    public String getPatch(Long fixId, String userEmail) {
        Fix fix = fixRepository.findById(fixId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Fix not found: " + fixId));
        if (fix.getFinding() == null || !isOwnedBy(fix.getFinding(), userEmail)) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Fix not found: " + fixId);
        }
        return fix.getSuggestedPatch() != null ? fix.getSuggestedPatch() : "";
    }

    public Fix approveFix(Long fixId, String userEmail) {
        Fix fix = fixRepository.findById(fixId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Fix not found: " + fixId));
        if (fix.getFinding() == null || !isOwnedBy(fix.getFinding(), userEmail)) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Fix not found: " + fixId);
        }
        fix.setStatus("APPROVED");
        Fix saved = fixRepository.save(fix);
        auditLogService.log("FIX_APPROVED", "Remediation fix ID " + fixId + " was approved");
        return saved;
    }

    public Fix rejectFix(Long fixId, String userEmail) {
        Fix fix = fixRepository.findById(fixId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Fix not found: " + fixId));
        if (fix.getFinding() == null || !isOwnedBy(fix.getFinding(), userEmail)) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Fix not found: " + fixId);
        }
        fix.setStatus("REJECTED");
        Fix saved = fixRepository.save(fix);
        auditLogService.log("FIX_REJECTED", "Remediation fix ID " + fixId + " was rejected");
        return saved;
    }

    private Finding ownedFinding(Long findingId, String userEmail) {
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Finding not found: " + findingId));
        if (!isOwnedBy(finding, userEmail)) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Finding not found: " + findingId);
        }
        return finding;
    }

    private boolean isOwnedBy(Finding finding, String userEmail) {
        if (finding.getScan() == null) return false;
        if (finding.getScan().getProject() != null && finding.getScan().getProject().getUser() != null) {
            return userEmail.equalsIgnoreCase(finding.getScan().getProject().getUser().getEmail());
        }
        return finding.getScan().getRepository() != null && finding.getScan().getRepository().getUser() != null
                && userEmail.equalsIgnoreCase(finding.getScan().getRepository().getUser().getEmail());
    }
}
