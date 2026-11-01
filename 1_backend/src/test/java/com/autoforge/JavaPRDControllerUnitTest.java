package com.autoforge;

import com.autoforge.dto.*;
import com.autoforge.entity.Finding;
import com.autoforge.entity.Scan;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.PolicyRepository;
import com.autoforge.repository.ProjectRepository;
import com.autoforge.repository.ScanRepository;
import com.autoforge.service.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JavaPRDControllerUnitTest {

    @Mock
    private FindingRepository findingRepository;

    @Mock
    private ScanRepository scanRepository;

    @Mock
    private ProjectRepository projectRepository;

    @Mock
    private PolicyRepository policyRepository;

    private MetricsService metricsService;
    private PolicyEngine policyEngine;
    private SarifService sarifService;

    @BeforeEach
    void setUp() {
        metricsService = new MetricsService(findingRepository, scanRepository);
        policyEngine = new PolicyEngine(findingRepository, scanRepository, policyRepository);
        sarifService = new SarifService(findingRepository);
    }

    @Test
    void testMetricsServiceExactFormula() {
        Scan scan = new Scan();
        scan.setId(101L);

        Finding criticalFinding = new Finding();
        criticalFinding.setId(1L);
        criticalFinding.setScan(scan);
        criticalFinding.setSeverity("CRITICAL");

        Finding highFinding = new Finding();
        highFinding.setId(2L);
        highFinding.setScan(scan);
        highFinding.setSeverity("HIGH");

        Finding mediumFinding = new Finding();
        mediumFinding.setId(3L);
        mediumFinding.setScan(scan);
        mediumFinding.setSeverity("MEDIUM");

        Finding lowFinding = new Finding();
        lowFinding.setId(4L);
        lowFinding.setScan(scan);
        lowFinding.setSeverity("LOW");

        when(findingRepository.findByScanId(101L))
                .thenReturn(List.of(criticalFinding, highFinding, mediumFinding, lowFinding));

        ScanMetricsResponse response = metricsService.getScanMetrics(101L);

        assertEquals(61, response.getHealthScore());
        assertEquals(4, response.getTotalFindings());
        assertEquals(1, response.getCounts().getCritical());
        assertEquals(1, response.getCounts().getHigh());
        assertEquals(1, response.getCounts().getMedium());
        assertEquals(1, response.getCounts().getLow());
    }

    @Test
    void testMetricsServiceEmptyFindingsGives100() {
        when(findingRepository.findByScanId(202L)).thenReturn(Collections.emptyList());

        ScanMetricsResponse response = metricsService.getScanMetrics(202L);
        assertEquals(100, response.getHealthScore());
        assertEquals(0, response.getTotalFindings());
    }

    @Test
    void testPolicyEngineEvaluatePassAndFail() {
        Scan scan = new Scan();
        scan.setId(303L);
        when(scanRepository.findById(303L)).thenReturn(Optional.of(scan));

        Finding high1 = new Finding();
        high1.setSeverity("HIGH");
        Finding high2 = new Finding();
        high2.setSeverity("HIGH");
        Finding high3 = new Finding();
        high3.setSeverity("HIGH");

        when(findingRepository.findByScanId(303L)).thenReturn(List.of(high1, high2, high3));

        PolicyEvaluationRequest request = new PolicyEvaluationRequest();
        request.setScanId(303L);
        request.setMaxCritical(0);
        request.setMaxHigh(2);

        PolicyEvaluationResponse eval = policyEngine.evaluate(request);
        assertFalse(eval.isPassed());
        assertEquals("FAIL", eval.getStatus());

        request.setMaxHigh(3);
        PolicyEvaluationResponse evalPass = policyEngine.evaluate(request);
        assertTrue(evalPass.isPassed());
        assertEquals("PASS", evalPass.getStatus());
    }

    @Test
    void testSarifServiceExportGeneration() {
        Scan scan = new Scan();
        scan.setId(404L);

        Finding finding = new Finding();
        finding.setId(10L);
        finding.setScan(scan);
        finding.setRuleId("SEC-XSS-001");
        finding.setTitle("Reflected XSS in search query");
        finding.setFilePath("src/main/resources/templates/search.html");
        finding.setLineNumber(28);
        finding.setSeverity("HIGH");

        when(findingRepository.findByScanId(404L)).thenReturn(List.of(finding));

        Map<String, Object> sarif = sarifService.generateSarifReport(404L);
        assertNotNull(sarif);
        assertEquals("2.1.0", sarif.get("version"));
        assertTrue(sarif.containsKey("runs"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> runs = (List<Map<String, Object>>) sarif.get("runs");
        assertFalse(runs.isEmpty());

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> results = (List<Map<String, Object>>) runs.get(0).get("results");
        assertEquals(1, results.size());
        assertEquals("SEC-XSS-001", results.get(0).get("ruleId"));
        assertEquals("error", results.get(0).get("level"));
    }

    @Test
    void testQueueServiceSchemaPayload() {
        QueueService queueService = new QueueService();
        queueService.publishScanJob(505L, 606L, "https://github.com/autoforge/repo", "abcdef123456", "main");

        assertFalse(queueService.getFallbackQueue().isEmpty());
        Map<String, Object> message = queueService.getFallbackQueue().peek();
        assertNotNull(message);

        assertEquals("505", message.get("job_id"));
        assertEquals("606", message.get("project_id"));
        assertEquals("https://github.com/autoforge/repo", message.get("repo_url"));
        assertEquals("abcdef123456", message.get("commit_sha"));
        assertEquals("main", message.get("branch"));

        assertEquals(505L, message.get("scan_id"));
        assertEquals(606L, message.get("repository_id"));
    }
}
