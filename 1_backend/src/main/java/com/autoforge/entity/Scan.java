package com.autoforge.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "scans")
@Getter
@Setter
@NoArgsConstructor
public class Scan {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "repository_id")
    private Repository repository;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id")
    private Project project;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "webhook_event_id")
    private WebhookEvent webhookEvent;

    @Column(name = "commit_sha", length = 64)
    private String commitSha;

    @Column(name = "branch", length = 64)
    private String branch = "main";

    @Column(name = "changed_file_paths", columnDefinition = "TEXT")
    private String changedFilePaths;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private ScanStatus status = ScanStatus.QUEUED;

    @Column(name = "error_message", length = 1024)
    private String errorMessage;

    @Column(name = "progress")
    private Integer progress = 0;

    @Column(name = "idempotency_key", length = 128)
    private String idempotencyKey;

    @Column(name = "source_path", length = 2048)
    private String sourcePath;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();
}
