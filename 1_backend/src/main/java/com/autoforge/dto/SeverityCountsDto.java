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
public class SeverityCountsDto {
    @JsonProperty("CRITICAL")
    private int critical;

    @JsonProperty("HIGH")
    private int high;

    @JsonProperty("MEDIUM")
    private int medium;

    @JsonProperty("LOW")
    private int low;
}
