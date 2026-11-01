package com.autoforge;

import com.autoforge.entity.AstMetrics;
import com.autoforge.entity.Finding;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.repository.*;
import com.autoforge.service.QueueService;
import com.autoforge.service.ScanService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ScoredResultIngestionTest {
    @Mock RepositoryRepository repositoryRepository;
    @Mock ProjectRepository projectRepository;
    @Mock WebhookEventRepository webhookEventRepository;
    @Mock ScanRepository scanRepository;
    @Mock VulnerabilityRepository vulnerabilityRepository;
    @Mock FindingRepository findingRepository;
    @Mock CallTraceRepository callTraceRepository;
    @Mock MLPredictionRepository mlPredictionRepository;
    @Mock QueueService queueService;
    @Mock AstMetricsRepository astMetricsRepository;

    private Scan scan;
    private ScanService scanService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        scan = new Scan();
        scan.setId(7L);
        scan.setStatus(ScanStatus.RUNNING);
        when(scanRepository.findById(7L)).thenReturn(Optional.of(scan));
        lenient().when(findingRepository.save(any(Finding.class))).thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(callTraceRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(mlPredictionRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(astMetricsRepository.findByScanId(7L)).thenReturn(Optional.empty());
        lenient().when(astMetricsRepository.save(any(AstMetrics.class))).thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(scanRepository.save(any(Scan.class))).thenAnswer(invocation -> invocation.getArgument(0));
        scanService = new ScanService(repositoryRepository, projectRepository, webhookEventRepository, scanRepository,
                vulnerabilityRepository, findingRepository, callTraceRepository, mlPredictionRepository,
                queueService, astMetricsRepository);
    }

    @Test
    void persistsFindingsTracesMetricsAndCompletesOnlyAfterValidResults() throws Exception {
        var result = objectMapper.readTree("""
                {
                  "job_id": 7,
                  "metrics": {"files_analyzed": 12},
                  "findings": [{
                    "rule_id": "SEC-1",
                    "title": "Unsafe query",
                    "file_path": "src/Dao.java",
                    "line_number": 18,
                    "severity": "high",
                    "code_snippet": "query(userInput)",
                    "is_reachable": true,
                    "reachability_status": "REACHABLE_CODE",
                    "priority": "P1",
                    "ml_confidence_score": 0.94,
                    "call_traces": [{
                      "step_number": 1,
                      "file_path": "src/Controller.java",
                      "line_number": 9,
                      "symbol_name": "handle"
                    }]
                  }]
                }
                """);

        scanService.persistScoredResults(7L, result);

        org.mockito.ArgumentCaptor<Finding> finding = org.mockito.ArgumentCaptor.forClass(Finding.class);
        verify(findingRepository).save(finding.capture());
        assertEquals("HIGH", finding.getValue().getSeverity());
        assertEquals("REACHABLE_CODE", finding.getValue().getReachabilityStatus());
        assertTrue(finding.getValue().getIsReachable());
        verify(callTraceRepository).save(any());
        verify(mlPredictionRepository).save(any());
        org.mockito.ArgumentCaptor<AstMetrics> metrics = org.mockito.ArgumentCaptor.forClass(AstMetrics.class);
        verify(astMetricsRepository).save(metrics.capture());
        assertTrue(metrics.getValue().getMetricsJson().contains("files_analyzed"));
        assertEquals(ScanStatus.COMPLETED, scan.getStatus());
        assertEquals(100, scan.getProgress());
    }

    @Test
    void rejectsMalformedFindingWithoutCompletingScan() throws Exception {
        var result = objectMapper.readTree("""
                {"job_id":7,"findings":[{"rule_id":"SEC-1","severity":"HIGH"}]}
                """);

        assertThrows(RuntimeException.class, () -> scanService.persistScoredResults(7L, result));

        verify(findingRepository, never()).save(any());
        verify(astMetricsRepository, never()).save(any());
        assertEquals(ScanStatus.RUNNING, scan.getStatus());
    }
}
