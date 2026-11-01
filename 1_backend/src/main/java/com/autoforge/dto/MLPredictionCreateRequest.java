package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MLPredictionCreateRequest {
    @NotNull
    @JsonProperty("finding_id")
    private Long findingId;

    @NotNull
    @DecimalMin("0.0")
    @DecimalMax("1.0")
    @JsonProperty("ml_confidence_score")
    private Double mlConfidenceScore;

    @JsonProperty("model_version")
    private String modelVersion = "v1.0.0";

    @JsonProperty("feature_vector_summary")
    private Object featureVectorSummary;
}
