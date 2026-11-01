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
public class RemediationGenerateResponse {
    @JsonProperty("id")
    private Long id;

    @JsonProperty("finding_id")
    private Long findingId;

    @JsonProperty("status")
    private String status;

    @JsonProperty("model_used")
    private String modelUsed;

    @JsonProperty("patch")
    private String patch;

    @JsonProperty("created_at")
    private Instant createdAt;
}
