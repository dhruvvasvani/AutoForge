package com.autoforge.service;

import com.autoforge.dto.ProjectMetricsResponse;
import com.autoforge.dto.ScanMetricsResponse;
import com.autoforge.dto.SeverityCountsDto;
import com.autoforge.entity.Finding;
import com.autoforge.entity.Scan;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.ScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MetricsService {
    private final FindingRepository findingRepository;
    private final ScanRepository scanRepository;

    public ScanMetricsResponse getScanMetrics(Long scanId) {
        List<Finding> findings = findingRepository.findByScanId(scanId);
        return calculateMetrics(String.valueOf(scanId), findings);
    }

    public ProjectMetricsResponse getProjectMetrics(Long projectId) {
        List<Scan> scans = scanRepository.findByProjectId(projectId);
        List<Finding> allFindings = findingRepository.findAllByProjectId(projectId);

        int critical = 0, high = 0, medium = 0, low = 0;
        for (Finding f : allFindings) {
            String sev = f.getSeverity() != null ? f.getSeverity().toUpperCase() : "MEDIUM";
            switch (sev) {
                case "CRITICAL" -> critical++;
                case "HIGH" -> high++;
                case "MEDIUM" -> medium++;
                case "LOW" -> low++;
            }
        }

        int latestHealthScore = 100;
        if (!scans.isEmpty()) {
            Scan latestScan = scans.get(scans.size() - 1);
            latestHealthScore = getScanMetrics(latestScan.getId()).getHealthScore();
        }

        return ProjectMetricsResponse.builder()
                .projectId(projectId)
                .totalScans(scans.size())
                .latestHealthScore(latestHealthScore)
                .totalFindings(allFindings.size())
                .counts(new SeverityCountsDto(critical, high, medium, low))
                .build();
    }

    private ScanMetricsResponse calculateMetrics(String scanId, List<Finding> findings) {
        int critical = 0, high = 0, medium = 0, low = 0;
        for (Finding f : findings) {
            String sev = f.getSeverity() != null ? f.getSeverity().toUpperCase() : "MEDIUM";
            switch (sev) {
                case "CRITICAL" -> critical++;
                case "HIGH" -> high++;
                case "MEDIUM" -> medium++;
                case "LOW" -> low++;
            }
        }

        int penalty = (critical * 25) + (high * 10) + (medium * 3) + (low * 1);
        int healthScore = Math.max(0, 100 - penalty);

        return ScanMetricsResponse.builder()
                .scanId(scanId)
                .counts(new SeverityCountsDto(critical, high, medium, low))
                .totalFindings(findings.size())
                .healthScore(healthScore)
                .build();
    }
}
