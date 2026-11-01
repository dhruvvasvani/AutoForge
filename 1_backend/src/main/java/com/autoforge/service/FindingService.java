package com.autoforge.service;

import com.autoforge.dto.CallTraceStepDto;
import com.autoforge.dto.FindingResponseDto;
import com.autoforge.entity.CallTrace;
import com.autoforge.entity.Finding;
import com.autoforge.repository.CallTraceRepository;
import com.autoforge.repository.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class FindingService {
    private final FindingRepository findingRepository;
    private final CallTraceRepository callTraceRepository;

    public List<FindingResponseDto> getFindingsByScan(Long scanId) {
        return findingRepository.findByScanId(scanId)
                .stream()
                .map(this::toResponseDto)
                .toList();
    }

    public List<FindingResponseDto> getFindingsByProject(Long projectId, String severity, String ruleId, int skip, int limit) {
        int pageNumber = skip / (limit > 0 ? limit : 10);
        int pageSize = limit > 0 ? limit : 10;
        PageRequest pageRequest = PageRequest.of(pageNumber, pageSize, Sort.by(Sort.Direction.DESC, "createdAt"));

        String filterSeverity = (severity != null && !severity.isBlank()) ? severity.toUpperCase() : null;
        String filterRule = (ruleId != null && !ruleId.isBlank()) ? ruleId : null;

        return findingRepository.findByProjectIdWithFilters(projectId, filterSeverity, filterRule, pageRequest)
                .stream()
                .map(this::toResponseDto)
                .toList();
    }

    public List<CallTraceStepDto> getCallTracesByFinding(Long findingId) {
        return callTraceRepository.findByFindingIdOrderByStepNumberAsc(findingId)
                .stream()
                .map(this::toTraceDto)
                .toList();
    }

    private FindingResponseDto toResponseDto(Finding finding) {
        List<CallTraceStepDto> traces = callTraceRepository.findByFindingIdOrderByStepNumberAsc(finding.getId())
                .stream()
                .map(this::toTraceDto)
                .toList();

        return FindingResponseDto.builder()
                .id(finding.getId())
                .scanId(finding.getScan().getId())
                .ruleId(finding.getRuleId())
                .title(finding.getTitle())
                .filePath(finding.getFilePath())
                .lineNumber(finding.getLineNumber())
                .severity(finding.getSeverity())
                .codeSnippet(finding.getCodeSnippet())
                .callTraces(traces)
                .build();
    }

    private CallTraceStepDto toTraceDto(CallTrace trace) {
        return CallTraceStepDto.builder()
                .stepNumber(trace.getStepNumber())
                .filePath(trace.getFilePath())
                .lineNumber(trace.getLineNumber())
                .symbolName(trace.getSymbolName())
                .build();
    }
}
