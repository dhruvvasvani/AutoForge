package com.autoforge.service;

import com.autoforge.dto.ScanFindingResponse;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.entity.Vulnerability;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.FixRepository;
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
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScanServiceTest {

    @Mock
    private RepositoryRepository repositoryRepository;
    @Mock
    private WebhookEventRepository webhookEventRepository;
    @Mock
    private ScanRepository scanRepository;
    @Mock
    private VulnerabilityRepository vulnerabilityRepository;
    @Mock
    private FixRepository fixRepository;
    @Mock
    private StringRedisTemplate redisTemplate;

    private ScanService scanService;

    @BeforeEach
    void setUp() {
        scanService = new ScanService(
                repositoryRepository,
                webhookEventRepository,
                scanRepository,
                vulnerabilityRepository,
                fixRepository,
                redisTemplate
        );
    }

    @Test
    void persistsTaggedAstResultsOnceWithReachabilityAndRisk() throws Exception {
        Scan scan = new Scan();
        scan.setId(8L);
        scan.setStatus(ScanStatus.RUNNING);
        when(scanRepository.findById(8L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(invocation -> invocation.getArgument(0));
        JsonNode tagged = new ObjectMapper().readTree(
                "[{\"source\":\"semgrep\",\"check_id\":\"SQLI\","
                        + "\"path\":\"src/app.py\",\"start\":{\"line\":12},"
                        + "\"extra\":{\"severity\":\"HIGH\",\"message\":\"Unsafe query\","
                        + "\"reachable\":true,\"combined_risk_score\":8.5,\"priority\":\"P1\"}}]"
        );

        scanService.persistScanResults(8L, tagged, tagged, null, tagged, 8.5);

        ArgumentCaptor<Vulnerability> findingCaptor = ArgumentCaptor.forClass(Vulnerability.class);
        verify(vulnerabilityRepository).save(findingCaptor.capture());
        Vulnerability finding = findingCaptor.getValue();
        assertEquals("SEMGREP", finding.getSourceScanner());
        assertEquals("src/app.py", finding.getFilePath());
        assertEquals(12, finding.getLineNumber());
        assertEquals("SQLI", finding.getRuleId());
        assertEquals(Boolean.TRUE, finding.getIsReachable());
        assertEquals(8.5, finding.getCombinedRiskScore());
        assertEquals("P1", finding.getPriority());
    }

    @Test
    void returnsFindingsOnlyForTheOwningUser() {
        when(scanRepository.findByIdAndRepositoryUserEmail(8L, "owner@example.com"))
                .thenReturn(Optional.empty());

        assertThrows(ApiException.class, () -> scanService.getScanFindings(8L, "owner@example.com"));

        verify(vulnerabilityRepository, never()).findByScanId(8L);
    }

    @Test
    void mapsPersistedFindingsToUserFacingResponse() {
        when(scanRepository.findByIdAndRepositoryUserEmail(8L, "owner@example.com"))
                .thenReturn(Optional.of(new Scan()));
        Vulnerability finding = new Vulnerability();
        finding.setId(15L);
        finding.setSourceScanner("AST");
        finding.setFilePath("src/app.py");
        finding.setLineNumber(12);
        finding.setRuleId("SQLI");
        finding.setSeverity("HIGH");
        finding.setIsReachable(Boolean.TRUE);
        finding.setCombinedRiskScore(8.5);
        finding.setPriority("P1");
        finding.setDescription("Untrusted input reaches query");
        when(vulnerabilityRepository.findByScanId(8L)).thenReturn(List.of(finding));

        List<ScanFindingResponse> results = scanService.getScanFindings(8L, "owner@example.com");

        assertEquals(1, results.size());
        assertEquals("AST", results.get(0).sourceScanner());
        assertEquals("src/app.py", results.get(0).filePath());
        assertEquals(Boolean.TRUE, results.get(0).reachable());
        assertEquals(8.5, results.get(0).combinedRiskScore());
        assertEquals("Untrusted input reaches query", results.get(0).description());
    }
}
