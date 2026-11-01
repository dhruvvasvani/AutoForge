package com.autoforge.service;

import com.autoforge.dto.*;
import com.autoforge.entity.Finding;
import com.autoforge.entity.Scan;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.ProjectRepository;
import com.autoforge.repository.ScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class DashboardService {
    private final ProjectRepository projectRepository;
    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final MetricsService metricsService;

    public DashboardSummaryResponse getSummary() {
        long totalProjects = projectRepository.count();
        long totalScans = scanRepository.count();
        List<Finding> allFindings = findingRepository.findAll();

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

        int penalty = (critical * 25) + (high * 10) + (medium * 3) + (low * 1);
        int avgHealth = totalScans == 0 ? 100 : Math.max(0, 100 - (int) (penalty / Math.max(1, totalScans)));

        return DashboardSummaryResponse.builder()
                .totalProjects(totalProjects)
                .totalScans(totalScans)
                .totalFindings(allFindings.size())
                .severityCounts(new SeverityCountsDto(critical, high, medium, low))
                .averageHealthScore(avgHealth)
                .build();
    }

    public List<ScanJobResponse> getRecentScans(int limit) {
        PageRequest pageRequest = PageRequest.of(0, limit > 0 ? limit : 10, Sort.by(Sort.Direction.DESC, "createdAt"));
        return scanRepository.findAll(pageRequest)
                .stream()
                .map(scan -> {
                    Long projId = scan.getProject() != null ? scan.getProject().getId() : (scan.getRepository() != null ? scan.getRepository().getId() : null);
                    return ScanJobResponse.builder()
                            .id(scan.getId())
                            .projectId(projId)
                            .commitSha(scan.getCommitSha())
                            .branch(scan.getBranch())
                            .status(scan.getStatus().name())
                            .errorMessage(scan.getErrorMessage())
                            .progress(scan.getProgress())
                            .createdAt(scan.getCreatedAt())
                            .completedAt(scan.getCompletedAt())
                            .build();
                })
                .toList();
    }

    public List<FindingResponseDto> getTopFindings(int limit) {
        PageRequest pageRequest = PageRequest.of(0, limit > 0 ? limit : 10, Sort.by(Sort.Direction.DESC, "createdAt"));
        return findingRepository.findAll(pageRequest)
                .stream()
                .filter(f -> "CRITICAL".equalsIgnoreCase(f.getSeverity()) || "HIGH".equalsIgnoreCase(f.getSeverity()))
                .map(f -> FindingResponseDto.builder()
                        .id(f.getId())
                        .scanId(f.getScan().getId())
                        .ruleId(f.getRuleId())
                        .title(f.getTitle())
                        .filePath(f.getFilePath())
                        .lineNumber(f.getLineNumber())
                        .severity(f.getSeverity())
                        .codeSnippet(f.getCodeSnippet())
                        .build())
                .toList();
    }

    public List<ScanMetricsResponse> getProjectMetricsHistory(Long projectId) {
        List<Scan> scans = scanRepository.findByProjectId(projectId);
        List<ScanMetricsResponse> history = new ArrayList<>();
        for (Scan s : scans) {
            history.add(metricsService.getScanMetrics(s.getId()));
        }
        return history;
    }
}
