package com.autoforge;

import com.autoforge.controller.GithubWebhookController;
import com.autoforge.controller.InternalScanController;
import com.autoforge.dto.ScanResultsPayload;
import com.autoforge.entity.*;
import com.autoforge.repository.*;
import com.autoforge.security.InternalApiKeyFilter;
import com.autoforge.service.QueueService;
import com.autoforge.service.RemediationService;
import com.autoforge.service.ScanService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ScanPipelineIntegrationTest {
    private final RepositoryRepository repositoryRepository = mock(RepositoryRepository.class);
    private final ProjectRepository projectRepository = mock(ProjectRepository.class);
    private final WebhookEventRepository webhookEventRepository = mock(WebhookEventRepository.class);
    private final ScanRepository scanRepository = mock(ScanRepository.class);
    private final VulnerabilityRepository vulnerabilityRepository = mock(VulnerabilityRepository.class);
    private final FindingRepository findingRepository = mock(FindingRepository.class);
    private final CallTraceRepository callTraceRepository = mock(CallTraceRepository.class);
    private final MLPredictionRepository mlPredictionRepository = mock(MLPredictionRepository.class);
    private final QueueService queueService = mock(QueueService.class);
    private final AstMetricsRepository astMetricsRepository = mock(AstMetricsRepository.class);
    private final RemediationService remediationService = mock(RemediationService.class);
    private final ScanService scanService = new ScanService(
            repositoryRepository, projectRepository, webhookEventRepository, scanRepository,
            vulnerabilityRepository, findingRepository, callTraceRepository, mlPredictionRepository,
            queueService, astMetricsRepository, remediationService);

    @BeforeEach
    void resetMocks() {
        reset(repositoryRepository, projectRepository, webhookEventRepository, scanRepository,
                vulnerabilityRepository, findingRepository, callTraceRepository, mlPredictionRepository,
                queueService, astMetricsRepository, remediationService);
    }

    @Test
    void duplicatePushReturnsExistingScanWithoutPublishingAnotherJob() {
        Repository repository = new Repository();
        repository.setId(3L);
        repository.setGithubRepoFullName("owner/repo");
        Scan existing = new Scan();
        existing.setId(12L);
        existing.setStatus(ScanStatus.COMPLETED);
        when(repositoryRepository.findByGithubRepoFullName("owner/repo")).thenReturn(Optional.of(repository));
        when(scanRepository.findFirstByRepositoryIdAndCommitSha(3L, "full-commit-sha"))
                .thenReturn(Optional.of(existing));

        var result = scanService.createOrGetScanJobFromPush(
                "owner/repo", "full-commit-sha", "push", "main", List.of());

        assertSame(existing, result.scan());
        assertFalse(result.created());
        verify(webhookEventRepository, never()).save(any());
        verify(scanRepository, never()).save(any());
        verifyNoInteractions(queueService);
    }

    @Test
    void workerPayloadPersistsPriorityReachabilityAndIgnoresAdditionalFields() throws Exception {
        Scan scan = new Scan();
        scan.setId(12L);
        scan.setStatus(ScanStatus.RUNNING);
        when(scanRepository.findById(12L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(invocation -> invocation.getArgument(0));
        ObjectMapper mapper = new ObjectMapper();
        ScanResultsPayload payload = mapper.readValue("""
                {
                  "repoFullName": "owner/repo",
                  "commitSha": "full-commit-sha",
                  "semgrep": [{
                    "check_id": "RULE-1",
                    "path": "src/main.py",
                    "start": {"line": 7},
                    "extra": {
                      "severity": "WARNING",
                      "message": "Example finding",
                      "reachable": false,
                      "reachability": "UNREACHABLE_NOISE",
                      "priority": "P2",
                      "combined_risk_score": 7.2,
                      "ai_fix": {"success": false}
                    }
                  }],
                  "checkov": [],
                  "tagged_findings": [],
                  "combinedRiskScore": 7.2
                }
                """, ScanResultsPayload.class);

        Scan result = scanService.persistScanResults(12L, payload);

        assertEquals(ScanStatus.COMPLETED, result.getStatus());
        assertEquals(100, result.getProgress());
        var findingCaptor = ArgumentCaptor.forClass(Finding.class);
        verify(findingRepository).save(findingCaptor.capture());
        assertEquals("RULE-1", findingCaptor.getValue().getRuleId());
        assertEquals("Example finding", findingCaptor.getValue().getTitle());
        assertEquals("P2", findingCaptor.getValue().getPriority());
        assertFalse(findingCaptor.getValue().getIsReachable());
        var vulnerabilityCaptor = ArgumentCaptor.forClass(Vulnerability.class);
        verify(vulnerabilityRepository).save(vulnerabilityCaptor.capture());
        assertEquals("P2", vulnerabilityCaptor.getValue().getPriority());
        assertFalse(vulnerabilityCaptor.getValue().getIsReachable());
    }

    @Test
    void workerFailureResultMarksScanFailed() throws Exception {
        Scan scan = new Scan();
        scan.setId(13L);
        scan.setStatus(ScanStatus.RUNNING);
        when(scanRepository.findById(13L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(invocation -> invocation.getArgument(0));
        ScanResultsPayload payload = new ObjectMapper().readValue(
                "{\"status\":\"FAILED\",\"error\":\"clone failed\"}", ScanResultsPayload.class);

        Scan result = scanService.persistScanResults(13L, payload);

        assertEquals(ScanStatus.FAILED, result.getStatus());
        assertEquals("clone failed", result.getErrorMessage());
        verifyNoInteractions(findingRepository, vulnerabilityRepository);
    }

    @Test
    void endToEndWebhookToWorkerToPersistedResultsFlow() throws Exception {
        String webhookSecret = "test-webhook-secret";
        String internalToken = "test-internal-token";

        // 1. Setup GitHub push event payload
        String rawPushPayload = """
                {
                  "ref": "refs/heads/main",
                  "after": "c0ffee1234567890abcdef1234567890abcdef12",
                  "repository": {
                    "full_name": "autoforge-team/sample-service",
                    "clone_url": "https://github.com/autoforge-team/sample-service.git"
                  },
                  "head_commit": {
                    "added": ["src/app.py"],
                    "modified": ["README.md"],
                    "removed": []
                  }
                }
                """;

        String signature = "sha256=" + computeHmac(rawPushPayload, webhookSecret);

        Repository mockRepo = new Repository();
        mockRepo.setId(99L);
        mockRepo.setGithubRepoFullName("autoforge-team/sample-service");
        when(repositoryRepository.findByGithubRepoFullName("autoforge-team/sample-service"))
                .thenReturn(Optional.of(mockRepo));

        Scan queuedScan = new Scan();
        queuedScan.setId(42L);
        queuedScan.setRepository(mockRepo);
        queuedScan.setCommitSha("c0ffee1234567890abcdef1234567890abcdef12");
        queuedScan.setBranch("main");
        queuedScan.setStatus(ScanStatus.QUEUED);

        when(scanRepository.findFirstByRepositoryIdAndCommitSha(eq(99L), anyString()))
                .thenReturn(Optional.empty());
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> {
            Scan s = inv.getArgument(0);
            if (s.getId() == null) s.setId(42L);
            return s;
        });
        when(scanRepository.findById(42L)).thenReturn(Optional.of(queuedScan));

        // 2. Dispatch push to Webhook Controller
        GithubWebhookController webhookController = new GithubWebhookController(scanService);
        ReflectionTestUtils.setField(webhookController, "webhookSecret", webhookSecret);

        ResponseEntity<Map<String, Object>> webhookResponse = webhookController.handlePush(
                rawPushPayload, signature, "push");

        assertEquals(HttpStatus.ACCEPTED, webhookResponse.getStatusCode());
        assertEquals("accepted", webhookResponse.getBody().get("status"));
        assertEquals(42L, webhookResponse.getBody().get("scan_id"));

        // Verify job was dispatched to QueueService
        verify(queueService).publishScanJob(
                eq(42L), eq(99L), eq("https://github.com/autoforge-team/sample-service"),
                eq("c0ffee1234567890abcdef1234567890abcdef12"), eq("main"), anyList());

        // 3. Worker completes scan and POSTs to InternalScanController via InternalApiKeyFilter
        InternalApiKeyFilter filter = new InternalApiKeyFilter(internalToken);

        // Prove wrong token gets 401
        MockHttpServletRequest rejectedReq = new MockHttpServletRequest("POST", "/api/internal/scans/42/results");
        rejectedReq.addHeader("X-AutoForge-Internal-Token", "wrong-secret");
        MockHttpServletResponse rejectedRes = new MockHttpServletResponse();
        filter.doFilter(rejectedReq, rejectedRes, new MockFilterChain());
        assertEquals(HttpStatus.UNAUTHORIZED.value(), rejectedRes.getStatus());

        // Prove correct pipeline token passes
        MockHttpServletRequest allowedReq = new MockHttpServletRequest("POST", "/api/internal/scans/42/results");
        allowedReq.addHeader("X-AutoForge-Internal-Token", internalToken);
        MockHttpServletResponse allowedRes = new MockHttpServletResponse();
        filter.doFilter(allowedReq, allowedRes, new MockFilterChain());
        assertEquals(HttpStatus.OK.value(), allowedRes.getStatus());

        // 4. Submit results payload to InternalScanController
        String workerResultsJson = """
                {
                  "repoFullName": "autoforge-team/sample-service",
                  "commitSha": "c0ffee1234567890abcdef1234567890abcdef12",
                  "semgrep": [{
                    "check_id": "SEC-SQL-01",
                    "path": "src/app.py",
                    "start": {"line": 15},
                    "extra": {
                      "severity": "CRITICAL",
                      "message": "SQL Injection vulnerability detected",
                      "reachable": true,
                      "reachability": "REACHABLE_CODE",
                      "priority": "P0"
                    }
                  }],
                  "checkov": [],
                  "tagged_findings": [],
                  "combinedRiskScore": 9.5
                }
                """;

        ScanResultsPayload payload = new ObjectMapper().readValue(workerResultsJson, ScanResultsPayload.class);
        InternalScanController internalScanController = new InternalScanController(scanService);
        var controllerResponse = internalScanController.submitResults(42L, payload);

        assertEquals(HttpStatus.OK, controllerResponse.getStatusCode());
        assertEquals("COMPLETED", controllerResponse.getBody().getStatus());

        // 5. Verify persisted scan state and findings
        assertEquals(ScanStatus.COMPLETED, queuedScan.getStatus());
        assertEquals(100, queuedScan.getProgress());

        ArgumentCaptor<Finding> findingCaptor = ArgumentCaptor.forClass(Finding.class);
        verify(findingRepository, atLeastOnce()).save(findingCaptor.capture());
        Finding savedFinding = findingCaptor.getValue();
        assertEquals("SEC-SQL-01", savedFinding.getRuleId());
        assertEquals("SQL Injection vulnerability detected", savedFinding.getTitle());
        assertEquals("src/app.py", savedFinding.getFilePath());
        assertEquals(15, savedFinding.getLineNumber());
        assertEquals("CRITICAL", savedFinding.getSeverity());
        assertEquals("P0", savedFinding.getPriority());
        assertTrue(savedFinding.getIsReachable());
    }

    private static String computeHmac(String data, String key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : rawHmac) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
