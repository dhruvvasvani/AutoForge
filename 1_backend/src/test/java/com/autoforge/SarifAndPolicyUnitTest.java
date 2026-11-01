package com.autoforge;

import com.autoforge.entity.CallTrace;
import com.autoforge.entity.Finding;
import com.autoforge.entity.Policy;
import com.autoforge.entity.Project;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.dto.PolicyEvaluationRequest;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.PolicyRepository;
import com.autoforge.repository.ScanRepository;
import com.autoforge.service.PolicyEngine;
import com.autoforge.service.SarifService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class SarifAndPolicyUnitTest {

    @Mock
    private FindingRepository findingRepository;
    @Mock
    private ScanRepository scanRepository;
    @Mock
    private PolicyRepository policyRepository;

    private SarifService sarifService;
    private PolicyEngine policyEngine;

    @BeforeEach
    void setUp() {
        sarifService = new SarifService(findingRepository);
        policyEngine = new PolicyEngine(findingRepository, scanRepository, policyRepository);
    }

    @Test
    void testSarifIncludesRulesFingerprintsAndCodeFlows() {
        Finding finding = new Finding();
        finding.setId(101L);
        finding.setRuleId("SEC-SQL-001");
        finding.setTitle("SQL Injection");
        finding.setSeverity("CRITICAL");
        finding.setFilePath("src/main/java/UserDao.java");
        finding.setLineNumber(45);
        finding.setCodeSnippet("db.query(sql);");

        CallTrace trace1 = new CallTrace();
        trace1.setStepNumber(1);
        trace1.setFilePath("src/main/java/UserController.java");
        trace1.setLineNumber(20);
        trace1.setSymbolName("handleRequest");

        finding.setCallTraces(List.of(trace1));

        when(findingRepository.findByScanId(500L)).thenReturn(List.of(finding));

        Map<String, Object> sarif = sarifService.generateSarifReport(500L);
        assertNotNull(sarif);
        assertEquals("2.1.0", sarif.get("version"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> runs = (List<Map<String, Object>>) sarif.get("runs");
        assertEquals(1, runs.size());

        Map<String, Object> run = runs.get(0);

        @SuppressWarnings("unchecked")
        Map<String, Object> tool = (Map<String, Object>) run.get("tool");
        @SuppressWarnings("unchecked")
        Map<String, Object> driver = (Map<String, Object>) tool.get("driver");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rules = (List<Map<String, Object>>) driver.get("rules");
        assertEquals(1, rules.size());
        assertEquals("SEC-SQL-001", rules.get(0).get("id"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> results = (List<Map<String, Object>>) run.get("results");
        assertEquals(1, results.size());
        Map<String, Object> result = results.get(0);
        assertEquals("SEC-SQL-001", result.get("ruleId"));
        assertEquals("error", result.get("level"));

        @SuppressWarnings("unchecked")
        Map<String, String> fingerprints = (Map<String, String>) result.get("partialFingerprints");
        assertNotNull(fingerprints);
        assertTrue(fingerprints.containsKey("primaryLocationLineHash"));

        assertTrue(result.containsKey("codeFlows"));
    }

    @Test
    void testPolicyEngineGetAndUpdateProjectPolicy() {
        Policy policy = new Policy();
        policy.setId(1L);
        policy.setMaxCritical(0);
        policy.setMaxHigh(1);

        when(policyRepository.findByProjectId(10L)).thenReturn(Optional.of(policy));

        var dto = policyEngine.getProjectPolicy(10L);
        assertEquals(0, dto.getMaxCritical());
        assertEquals(1, dto.getMaxHigh());
    }

    @Test
    void policyEvaluationUsesSavedProjectThresholdUnlessRequestOverridesIt() {
        Project project = new Project();
        project.setId(10L);
        Scan scan = new Scan();
        scan.setId(700L);
        scan.setProject(project);
        scan.setStatus(ScanStatus.COMPLETED);
        Finding high = new Finding();
        high.setSeverity("HIGH");
        Policy policy = new Policy();
        policy.setMaxCritical(0);
        policy.setMaxHigh(1);
        when(scanRepository.findById(700L)).thenReturn(Optional.of(scan));
        when(policyRepository.findByProjectId(10L)).thenReturn(Optional.of(policy));
        when(findingRepository.findByScanId(700L)).thenReturn(List.of(high));

        PolicyEvaluationRequest request = new PolicyEvaluationRequest();
        request.setScanId(700L);
        assertTrue(policyEngine.evaluate(request).isPassed());

        request.setMaxHigh(0);
        assertFalse(policyEngine.evaluate(request).isPassed());
    }

    @Test
    void policyGateExcludesExplicitlyUnreachableCriticalFindings() {
        Project project = new Project();
        project.setId(10L);
        Scan scan = new Scan();
        scan.setId(701L);
        scan.setProject(project);
        Finding unreachableCritical = new Finding();
        unreachableCritical.setSeverity("CRITICAL");
        unreachableCritical.setReachabilityStatus("UNREACHABLE_NOISE");
        Finding reachableCritical = new Finding();
        reachableCritical.setSeverity("CRITICAL");
        reachableCritical.setReachabilityStatus("REACHABLE_CODE");
        Policy policy = new Policy();
        policy.setMaxCritical(0);
        policy.setMaxHigh(2);
        when(scanRepository.findById(701L)).thenReturn(Optional.of(scan));
        when(policyRepository.findByProjectId(10L)).thenReturn(Optional.of(policy));
        when(findingRepository.findByScanId(701L)).thenReturn(List.of(unreachableCritical));

        PolicyEvaluationRequest request = new PolicyEvaluationRequest();
        request.setScanId(701L);
        assertTrue(policyEngine.evaluate(request).isPassed());

        when(findingRepository.findByScanId(701L)).thenReturn(List.of(unreachableCritical, reachableCritical));
        assertFalse(policyEngine.evaluate(request).isPassed());
    }
}
