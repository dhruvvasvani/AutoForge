package com.autoforge.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanDetailResultResponse {
    private Long scanId;
    private Long projectId;
    private String commitSha;
    private String branch;
    private String status;
    private String errorMessage;
    private Integer progress;
    private Instant createdAt;
    private Instant startedAt;
    private Instant completedAt;
    private Integer totalFindings;
    private SeverityCountsDto severityCounts;
    private Integer healthScore;
    private List<FindingResponseDto> findings;
    private List<MLPredictionResponseDto> mlPredictions;
}
