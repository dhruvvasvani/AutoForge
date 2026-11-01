package com.autoforge;

import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.dto.PolicyEvaluationResponse;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.ScanRepository;
import com.autoforge.service.PdfReportService;
import com.autoforge.service.PolicyEngine;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PdfReportServiceTest {
    @Test
    void generatesPdfForAuthorizedScan() {
        ScanRepository scans = mock(ScanRepository.class);
        FindingRepository findings = mock(FindingRepository.class);
        PolicyEngine policyEngine = mock(PolicyEngine.class);
        Scan scan = new Scan();
        scan.setId(22L);
        scan.setStatus(ScanStatus.COMPLETED);
        when(scans.findVisibleScanById(22L, "owner@example.com")).thenReturn(Optional.of(scan));
        when(findings.findByScanId(22L)).thenReturn(List.of());
        when(policyEngine.evaluate(any())).thenReturn(PolicyEvaluationResponse.builder()
                .status("PASS").reason("No blocking findings.").passed(true).build());

        byte[] report = new PdfReportService(scans, findings, policyEngine).generate(22L, "owner@example.com");

        assertTrue(new String(report, 0, 5, java.nio.charset.StandardCharsets.ISO_8859_1).startsWith("%PDF-"));
    }

    @Test
    void hidesPdfWhenScanIsNotOwnedByRequester() {
        ScanRepository scans = mock(ScanRepository.class);
        FindingRepository findings = mock(FindingRepository.class);
        PolicyEngine policyEngine = mock(PolicyEngine.class);
        when(scans.findVisibleScanById(22L, "other@example.com")).thenReturn(Optional.empty());

        assertThrows(ApiException.class, () -> new PdfReportService(scans, findings, policyEngine)
                .generate(22L, "other@example.com"));
        verifyNoInteractions(findings);
    }
}
