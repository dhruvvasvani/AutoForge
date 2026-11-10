package com.autoforge.service;

import com.autoforge.entity.AstMetrics;
import com.autoforge.entity.Finding;
import com.autoforge.entity.MLPrediction;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.AstMetricsRepository;
import com.autoforge.repository.CallTraceRepository;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.MLPredictionRepository;
import com.autoforge.repository.ProjectRepository;
import com.autoforge.repository.RepositoryRepository;
import com.autoforge.repository.ScanRepository;
import com.autoforge.repository.VulnerabilityRepository;
import com.autoforge.repository.WebhookEventRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScanServiceTest {

    @Mock private RepositoryRepository repositoryRepository;
    @Mock private ProjectRepository projectRepository;
    @Mock private WebhookEventRepository webhookEventRepository;
    @Mock private ScanRepository scanRepository;
    @Mock private VulnerabilityRepository vulnerabilityRepository;
    @Mock private FindingRepository findingRepository;
    @Mock private CallTraceRepository callTraceRepository;
    @Mock private MLPredictionRepository mlPredictionRepository;
    @Mock private QueueService queueService;
    @Mock private AstMetricsRepository astMetricsRepository;

    private ScanService scanService;

    @BeforeEach
    void setUp() {
        scanService = new ScanService(
                repositoryRepository,
                projectRepository,
                webhookEventRepository,
                scanRepository,
                vulnerabilityRepository,
                findingRepository,
                callTraceRepository,
                mlPredictionRepository,
                queueService,
                astMetricsRepository
        );
    }

    @Test
    void persistsScoredFindingsAndCompletesScan() throws Exception {
        Scan scan = new Scan();
        scan.setId(8L);
        scan.setStatus(ScanStatus.RUNNING);
        when(scanRepository.findById(8L)).thenReturn(Optional.of(scan));
        when(findingRepository.save(any(Finding.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(mlPredictionRepository.save(any(MLPrediction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        JsonNode results = new ObjectMapper().readTree(
                "{\"findings\":[{\"rule_id\":\"SQLI\",\"title\":\"Unsafe query\","
                        + "\"file_path\":\"src/app.py\",\"line_number\":12,"
                        + "\"severity\":\"HIGH\",\"is_reachable\":true,"
                        + "\"priority\":\"P1\",\"ml_confidence_score\":0.73}]}"
        );

        scanService.persistScoredResults(8L, results);

        ArgumentCaptor<Finding> findingCaptor = ArgumentCaptor.forClass(Finding.class);
        verify(findingRepository).save(findingCaptor.capture());
        Finding finding = findingCaptor.getValue();
        assertEquals("SQLI", finding.getRuleId());
        assertEquals("Unsafe query", finding.getTitle());
        assertEquals("src/app.py", finding.getFilePath());
        assertEquals(12, finding.getLineNumber());
        assertEquals("HIGH", finding.getSeverity());
        assertEquals(Boolean.TRUE, finding.getIsReachable());
        assertEquals("P1", finding.getPriority());
        verify(mlPredictionRepository).save(any(MLPrediction.class));
        verify(astMetricsRepository).save(any(AstMetrics.class));
        verify(scanRepository).save(scan);
        assertEquals(ScanStatus.COMPLETED, scan.getStatus());
        assertEquals(100, scan.getProgress());
    }

    @Test
    void rejectsFindingsMissingRequiredFields() throws Exception {
        Scan scan = new Scan();
        scan.setId(8L);
        when(scanRepository.findById(8L)).thenReturn(Optional.of(scan));
        JsonNode results = new ObjectMapper().readTree(
                "{\"findings\":[{\"rule_id\":\"SQLI\",\"severity\":\"HIGH\"}]}"
        );

        ApiException error = assertThrows(
                ApiException.class,
                () -> scanService.persistScoredResults(8L, results)
        );

        assertEquals(HttpStatus.BAD_REQUEST, error.getStatus());
        verify(findingRepository, never()).save(any(Finding.class));
    }
}
