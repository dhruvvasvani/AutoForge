package com.autoforge.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(
        name = "finding_feedback",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_finding_feedback_user_key",
                columnNames = {"user_id", "finding_key"}
        ),
        indexes = @Index(name = "idx_finding_feedback_review", columnList = "review_status, created_at")
)
@Getter
@Setter
@NoArgsConstructor
public class FindingFeedback {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "finding_key", nullable = false, length = 256)
    private String findingKey;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private Label label;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String sourceSnippet;

    @Column(nullable = false, length = 2000)
    private String reason;

    @Enumerated(EnumType.STRING)
    @Column(name = "review_status", nullable = false, length = 16)
    private ReviewStatus reviewStatus = ReviewStatus.PENDING;

    @Column(name = "reviewed_by", length = 150)
    private String reviewedBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "reviewed_at")
    private Instant reviewedAt;

    @Column(name = "trained_at")
    private Instant trainedAt;

    public enum Label {
        FALSE_POSITIVE,
        CONFIRMED_VULNERABILITY
    }

    public enum ReviewStatus {
        PENDING,
        APPROVED,
        REJECTED
    }
}
