package com.autoforge.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "scan_metrics", indexes = {
        @Index(name = "idx_scan_metrics_user_timestamp", columnList = "user_id, scan_timestamp")
})
@Getter
@Setter
@NoArgsConstructor
public class ScanMetrics {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "scan_timestamp", nullable = false)
    private Instant scanTimestamp;

    @Column(name = "metrics_json", nullable = false, length = 262144)
    private String metricsJson;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();
}
