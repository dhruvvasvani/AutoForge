package com.autoforge.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "fixes")
@Getter
@Setter
@NoArgsConstructor
public class Fix {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "vulnerability_id")
    private Vulnerability vulnerability;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "finding_id")
    private Finding finding;

    @Column(name = "file_path", length = 512)
    private String filePath;

    @Column(name = "status", length = 30)
    private String status = "PENDING";

    @Column(name = "suggested_patch", columnDefinition = "TEXT")
    private String suggestedPatch;

    @Column(name = "model_used", length = 100)
    private String modelUsed = "gemini-2.5-flash";

    @Column(nullable = false)
    private Boolean validated = false;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();
}
