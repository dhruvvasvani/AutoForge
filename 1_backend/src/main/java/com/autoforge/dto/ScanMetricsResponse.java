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
public class ScanMetricsResponse {
    @JsonProperty("scan_id")
    private String scanId;

    @JsonProperty("counts")
    private SeverityCountsDto counts;

    @JsonProperty("total_findings")
    private int totalFindings;

    @JsonProperty("health_score")
    private int healthScore;
}
