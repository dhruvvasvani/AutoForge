package com.autoforge.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "webhook_events")
@Getter
@Setter
@NoArgsConstructor
public class WebhookEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "repository_id")
    private Repository repository;

    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType;

    @Column(name = "commit_sha", length = 64)
    private String commitSha;

    @Column(name = "received_at", nullable = false, updatable = false)
    private Instant receivedAt = Instant.now();
}
