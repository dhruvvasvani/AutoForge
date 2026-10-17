package com.autoforge.service;

import com.autoforge.entity.Repository;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.entity.Vulnerability;
import com.autoforge.entity.WebhookEvent;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.RepositoryRepository;
import com.autoforge.repository.ScanRepository;
import com.autoforge.repository.VulnerabilityRepository;
import com.autoforge.repository.WebhookEventRepository;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class ScanService {

    private final RepositoryRepository repositoryRepository;
    private final WebhookEventRepository webhookEventRepository;
    private final ScanRepository scanRepository;
    private final VulnerabilityRepository vulnerabilityRepository;

    public Scan createScanJobFromPush(String repoFullName, String commitSha, String eventType) {
        Repository repository = repositoryRepository.findByGithubRepoFullName(repoFullName)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND,
                        "Repository is not connected to AutoForge: " + repoFullName));

        WebhookEvent event = new WebhookEvent();
        event.setRepository(repository);
        event.setEventType(eventType);
        event.setCommitSha(commitSha);
        webhookEventRepository.save(event);

        Scan scan = new Scan();
        scan.setRepository(repository);
        scan.setWebhookEvent(event);
        scan.setCommitSha(commitSha);
        scan.setStatus(ScanStatus.QUEUED);

        return scanRepository.save(scan);
    }

    public Scan persistScanResults(Long scanId, JsonNode semgrepFindings, JsonNode checkovFindings) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));

        if (semgrepFindings != null) {
            semgrepFindings.forEach(f -> vulnerabilityRepository.save(toVulnerability(scan, f, "SEMGREP")));
        }
        if (checkovFindings != null) {
            checkovFindings.forEach(f -> vulnerabilityRepository.save(toVulnerability(scan, f, "CHECKOV")));
        }

        scan.setStatus(ScanStatus.COMPLETED);
        scan.setCompletedAt(Instant.now());
        return scanRepository.save(scan);
    }

    private Vulnerability toVulnerability(Scan scan, JsonNode finding, String sourceScanner) {
        Vulnerability v = new Vulnerability();
        v.setScan(scan);
        v.setSourceScanner(sourceScanner);
        v.setFilePath(finding.path("path").asText(finding.path("file_abs_path").asText(null)));
        v.setLineNumber(finding.path("start").path("line").asInt(0));
        v.setRuleId(finding.path("check_id").asText(finding.path("check_id").asText(null)));
        v.setSeverity(finding.path("extra").path("severity").asText("MEDIUM"));
        v.setDescription(finding.path("extra").path("message").asText(finding.path("check_name").asText("")));
        return v;
    }
}

