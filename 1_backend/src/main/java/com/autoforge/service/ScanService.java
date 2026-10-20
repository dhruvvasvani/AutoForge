package com.autoforge.service;

import com.autoforge.entity.Fix;
import com.autoforge.entity.Repository;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.entity.Vulnerability;
import com.autoforge.entity.WebhookEvent;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.FixRepository;
import com.autoforge.repository.RepositoryRepository;
import com.autoforge.repository.ScanRepository;
import com.autoforge.repository.VulnerabilityRepository;
import com.autoforge.repository.WebhookEventRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ScanService {

    /** Redis list the pipeline worker consumes (2_pipeline/queue/worker.py). */
    private static final String SCAN_QUEUE = "scan_jobs";

    private final RepositoryRepository repositoryRepository;
    private final WebhookEventRepository webhookEventRepository;
    private final ScanRepository scanRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final FixRepository fixRepository;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

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

        Scan saved = scanRepository.save(scan);
        enqueueScanJob(saved, repoFullName, commitSha);
        return saved;
    }

    /** Agreed job schema: {repoFullName, commitSha, scan_id, repo_url}. */
    private void enqueueScanJob(Scan scan, String repoFullName, String commitSha) {
        try {
            Map<String, Object> job = new LinkedHashMap<>();
            job.put("repoFullName", repoFullName);
            job.put("commitSha", commitSha);
            job.put("scan_id", scan.getId());
            job.put("repo_url", "https://github.com/" + repoFullName + ".git");
            redisTemplate.opsForList().rightPush(SCAN_QUEUE, objectMapper.writeValueAsString(job));
        } catch (Exception e) {
            scan.setStatus(ScanStatus.FAILED);
            scanRepository.save(scan);
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "Could not queue scan: " + e.getMessage());
        }
    }

    public Scan persistScanResults(Long scanId, JsonNode semgrepFindings, JsonNode checkovFindings,
                                   JsonNode astFindings, Double combinedRiskScore) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));

        if (semgrepFindings != null) {
            semgrepFindings.forEach(f -> saveFinding(scan, f, "SEMGREP"));
        }
        if (checkovFindings != null) {
            checkovFindings.forEach(f -> saveFinding(scan, f, "CHECKOV"));
        }
        if (astFindings != null) {
            astFindings.forEach(f -> saveFinding(scan, f, "AST"));
        }

        scan.setCombinedRiskScore(combinedRiskScore);
        scan.setStatus(ScanStatus.COMPLETED);
        scan.setCompletedAt(Instant.now());
        return scanRepository.save(scan);
    }

    /** Saves one finding and, if the worker attached an AI fix, the Fix row too. */
    private void saveFinding(Scan scan, JsonNode finding, String sourceScanner) {
        Vulnerability v = vulnerabilityRepository.save(toVulnerability(scan, finding, sourceScanner));
        JsonNode aiFix = finding.path("ai_fix");
        if (aiFix.path("success").asBoolean(false)) {
            JsonNode result = aiFix.path("result");
            Fix fix = new Fix();
            fix.setVulnerability(v);
            fix.setSuggestedPatch(result.isTextual() ? result.asText() : result.toString());
            fixRepository.save(fix);
        }
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
        v.setIsReachable(finding.path("extra").path("reachable").isBoolean()
                ? finding.path("extra").path("reachable").asBoolean() : null);
        v.setCombinedRiskScore(finding.path("extra").path("combined_risk_score").isNumber()
                ? finding.path("extra").path("combined_risk_score").asDouble() : null);
        v.setPriority(finding.path("extra").path("priority").asText(null));
        return v;
    }
}