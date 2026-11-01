package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HybridScanPayload {
    @NotNull
    @JsonProperty("job_id")
    private Long jobId;

    @JsonProperty("project_id")
    private Long projectId;

    @JsonProperty("commit_sha")
    private String commitSha;

    @JsonProperty("overall_risk_score")
    private Double overallRiskScore;

    @JsonProperty("findings")
    @Builder.Default
    private List<HybridFindingDto> findings = new ArrayList<>();
}
