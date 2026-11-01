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
public class MLPredictionResponseDto {
    @JsonProperty("id")
    private Long id;

    @JsonProperty("finding_id")
    private Long findingId;

    @JsonProperty("ml_confidence_score")
    private Double mlConfidenceScore;

    @JsonProperty("model_version")
    private String modelVersion;

    @JsonProperty("feature_vector_summary")
    private String featureVectorSummary;

    @JsonProperty("created_at")
    private java.time.Instant createdAt;
}
