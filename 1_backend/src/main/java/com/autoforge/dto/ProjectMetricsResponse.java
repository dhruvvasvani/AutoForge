package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProjectMetricsResponse {
    @JsonProperty("project_id")
    private Long projectId;

    @JsonProperty("total_scans")
    private int totalScans;

    @JsonProperty("latest_health_score")
    private int latestHealthScore;

    @JsonProperty("total_findings")
    private int totalFindings;

    @JsonProperty("counts")
    private SeverityCountsDto counts;
}
