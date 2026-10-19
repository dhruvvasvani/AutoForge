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
    @JoinColumn(name = "vulnerability_id", nullable = false)
    private Vulnerability vulnerability;

    @Column(name = "suggested_patch", columnDefinition = "TEXT")
    private String suggestedPatch;

    @Column(name = "model_used")
    private String modelUsed = "gemini-2.5-flash";

    @Column(nullable = false)
    private Boolean validated = false;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();
}
