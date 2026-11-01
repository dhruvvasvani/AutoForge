package com.autoforge;

import com.autoforge.controller.DashboardController;
import com.autoforge.dto.DashboardSummaryResponse;
import com.autoforge.dto.FindingResponseDto;
import com.autoforge.dto.ScanJobResponse;
import com.autoforge.dto.ScanMetricsResponse;
import com.autoforge.entity.Finding;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.ProjectRepository;
import com.autoforge.repository.ScanRepository;
import com.autoforge.service.DashboardService;
import com.autoforge.service.MetricsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class DashboardAndMetricsUnitTest {

    @Mock
    private ProjectRepository projectRepository;
    @Mock
    private ScanRepository scanRepository;
    @Mock
    private FindingRepository findingRepository;
    @Mock
    private MetricsService metricsService;

    private DashboardService dashboardService;
    private DashboardController dashboardController;

    @BeforeEach
    void setUp() {
        dashboardService = new DashboardService(projectRepository, scanRepository, findingRepository, metricsService);
        dashboardController = new DashboardController(dashboardService);
    }

    @Test
    void testGetSummaryCalculatesTotalsAndCounts() {
        when(projectRepository.count()).thenReturn(5L);
        when(scanRepository.count()).thenReturn(20L);

        Finding critical = new Finding();
        critical.setSeverity("CRITICAL");
        Finding high = new Finding();
        high.setSeverity("HIGH");

        when(findingRepository.findAll()).thenReturn(List.of(critical, high));

        ResponseEntity<DashboardSummaryResponse> response = dashboardController.getSummary();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(5L, response.getBody().getTotalProjects());
        assertEquals(20L, response.getBody().getTotalScans());
        assertEquals(2L, response.getBody().getTotalFindings());
        assertNotNull(response.getBody().getSeverityCounts());
        assertEquals(1, response.getBody().getSeverityCounts().getCritical());
        assertEquals(1, response.getBody().getSeverityCounts().getHigh());
    }

    @Test
    void testGetRecentScans() {
        Scan scan = new Scan();
        scan.setId(10L);
        scan.setStatus(ScanStatus.COMPLETED);

        Page<Scan> page = new PageImpl<>(List.of(scan));
        when(scanRepository.findAll(any(Pageable.class))).thenReturn(page);

        ResponseEntity<List<ScanJobResponse>> response = dashboardController.getRecentScans(5);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(1, response.getBody().size());
        assertEquals(10L, response.getBody().get(0).getId());
    }

    @Test
    void testGetTopFindings() {
        Scan scan = new Scan();
        scan.setId(1L);

        Finding finding = new Finding();
        finding.setId(99L);
        finding.setScan(scan);
        finding.setSeverity("CRITICAL");
        finding.setTitle("Remote Code Execution");

        Page<Finding> page = new PageImpl<>(List.of(finding));
        when(findingRepository.findAll(any(Pageable.class))).thenReturn(page);

        ResponseEntity<List<FindingResponseDto>> response = dashboardController.getTopFindings(5);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(1, response.getBody().size());
        assertEquals("CRITICAL", response.getBody().get(0).getSeverity());
    }

    @Test
    void testProjectMetricsHistory() {
        Scan scan1 = new Scan();
        scan1.setId(1L);
        Scan scan2 = new Scan();
        scan2.setId(2L);

        when(scanRepository.findByProjectId(100L)).thenReturn(List.of(scan1, scan2));
        when(metricsService.getScanMetrics(anyLong())).thenReturn(ScanMetricsResponse.builder().healthScore(100).build());

        List<ScanMetricsResponse> history = dashboardService.getProjectMetricsHistory(100L);
        assertEquals(2, history.size());
        assertEquals(100, history.get(0).getHealthScore());
        assertEquals(100, history.get(1).getHealthScore());
    }
}
