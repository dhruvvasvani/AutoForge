package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PolicyEvaluationRequest {
    @NotNull
    @JsonProperty("scan_id")
    private Long scanId;

    @JsonProperty("max_critical")
    @Min(0)
    private Integer maxCritical;

    @JsonProperty("max_high")
    @Min(0)
    private Integer maxHigh;
}
