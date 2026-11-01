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
public class DashboardSummaryResponse {
    @JsonProperty("total_projects")
    private long totalProjects;

    @JsonProperty("total_scans")
    private long totalScans;

    @JsonProperty("total_findings")
    private long totalFindings;

    @JsonProperty("severity_counts")
    private SeverityCountsDto severityCounts;

    @JsonProperty("average_health_score")
    private int averageHealthScore;
}
