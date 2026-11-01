package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProjectPolicyDto {
    @JsonProperty("project_id")
    private Long projectId;

    @JsonProperty("max_critical")
    private Integer maxCritical;

    @JsonProperty("max_high")
    private Integer maxHigh;

    @JsonProperty("updated_at")
    private Instant updatedAt;
}
