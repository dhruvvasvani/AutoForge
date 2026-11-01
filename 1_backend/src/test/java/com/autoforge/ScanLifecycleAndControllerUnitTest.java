package com.autoforge;

import com.autoforge.controller.ScanController;
import com.autoforge.dto.ScanDetailResultResponse;
import com.autoforge.dto.ScanJobResponse;
import com.autoforge.dto.ScanStatusUpdateRequest;
import com.autoforge.dto.ScanTriggerRequest;
import com.autoforge.entity.Project;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.repository.*;
import com.autoforge.service.QueueService;
import com.autoforge.service.ScanExecutionService;
import com.autoforge.service.ScanService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ScanLifecycleAndControllerUnitTest {

    @Mock
    private RepositoryRepository repositoryRepository;
    @Mock
    private ProjectRepository projectRepository;
    @Mock
    private WebhookEventRepository webhookEventRepository;
    @Mock
    private ScanRepository scanRepository;
    @Mock
    private VulnerabilityRepository vulnerabilityRepository;
    @Mock
    private FindingRepository findingRepository;
    @Mock
    private CallTraceRepository callTraceRepository;
    @Mock
    private MLPredictionRepository mlPredictionRepository;
    @Mock
    private QueueService queueService;
    @Mock
    private AstMetricsRepository astMetricsRepository;
    @Mock
    private ScanExecutionService scanExecutionService;

    private ScanService scanService;
    private ScanController scanController;

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
        scanController = new ScanController(scanService, scanExecutionService);
    }

    @Test
    void testTriggerScanCreatesQueuedJobAndPublishesToQueue() {
        Project project = new Project();
        project.setId(10L);
        project.setRepoUrl("https://github.com/autoforge/demo");
        project.setDefaultBranch("main");

        Scan scan = new Scan();
        scan.setId(101L);
        scan.setProject(project);
        scan.setCommitSha("abcdef123");
        scan.setStatus(ScanStatus.QUEUED);

        when(projectRepository.findById(10L)).thenReturn(Optional.of(project));
        when(scanRepository.save(any(Scan.class))).thenReturn(scan);

        ScanTriggerRequest request = new ScanTriggerRequest();
        request.setProjectId(10L);
        request.setCommitSha("abcdef123");

        ResponseEntity<ScanJobResponse> response = scanController.triggerScan(request);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(101L, response.getBody().getId());
        assertEquals("QUEUED", response.getBody().getStatus());

        verify(queueService, times(1)).publishScanJob(eq(101L), eq(10L), eq("https://github.com/autoforge/demo"), eq("abcdef123"), eq("main"));
    }

    @Test
    void testTriggerScanIdempotency() {
        Project project = new Project();
        project.setId(10L);
        Scan existing = new Scan();
        existing.setId(99L);
        existing.setProject(project);
        existing.setCommitSha("abcdef123");
        existing.setStatus(ScanStatus.QUEUED);
        existing.setIdempotencyKey("unique-key-1");

        when(scanRepository.findByIdempotencyKey("unique-key-1")).thenReturn(Optional.of(existing));

        ScanTriggerRequest request = new ScanTriggerRequest();
        request.setProjectId(10L);
        request.setCommitSha("abcdef123");
        request.setIdempotencyKey("unique-key-1");

        ResponseEntity<ScanJobResponse> response = scanController.triggerScan(request);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(99L, response.getBody().getId());
        verify(queueService, never()).publishScanJob(any(), any(), any(), any(), any());
    }

    @Test
    void testUpdateScanStatusTransitions() {
        Scan scan = new Scan();
        scan.setId(202L);
        scan.setStatus(ScanStatus.QUEUED);

        when(scanRepository.findById(202L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(invocation -> invocation.getArgument(0));

        ScanStatusUpdateRequest updateReq = new ScanStatusUpdateRequest();
        updateReq.setStatus("PROCESSING");

        ResponseEntity<ScanJobResponse> response = scanController.updateScanStatus(202L, updateReq);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("PROCESSING", response.getBody().getStatus());
        assertNotNull(scan.getStartedAt());
    }

    @Test
    void testGetScanResultsDetail() {
        Scan scan = new Scan();
        scan.setId(303L);
        scan.setStatus(ScanStatus.COMPLETED);

        when(scanRepository.findById(303L)).thenReturn(Optional.of(scan));
        when(findingRepository.findByScanId(303L)).thenReturn(Collections.emptyList());
        when(mlPredictionRepository.findByFindingScanId(303L)).thenReturn(Collections.emptyList());

        ResponseEntity<ScanDetailResultResponse> response = scanController.getScanResults(303L);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(100, response.getBody().getHealthScore());
        assertEquals(0, response.getBody().getTotalFindings());
    }

    @Test
    void testListScansReturnsPaginatedResults() {
        when(scanRepository.findVisibleToUser(eq("dev@example.com"), any(org.springframework.data.domain.Pageable.class)))
                .thenReturn(new org.springframework.data.domain.PageImpl<>(Collections.emptyList()));

        ResponseEntity<java.util.List<ScanJobResponse>> response = scanController.listScans(
                0, 10, new UsernamePasswordAuthenticationToken("dev@example.com", null));

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().isEmpty());
    }
}
