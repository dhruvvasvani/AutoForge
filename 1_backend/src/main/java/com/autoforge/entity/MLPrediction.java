package com.autoforge.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "ml_predictions")
@Getter
@Setter
@NoArgsConstructor
public class MLPrediction {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "finding_id", nullable = false)
    private Finding finding;

    @Column(name = "ml_confidence_score", nullable = false)
    private Double mlConfidenceScore;

    @Column(name = "model_version", length = 64)
    private String modelVersion = "v1.0.0";

    @Column(name = "feature_vector_summary", columnDefinition = "TEXT")
    private String featureVectorSummary;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();
}
