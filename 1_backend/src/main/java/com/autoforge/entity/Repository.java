package com.autoforge.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "repositories")
@Getter
@Setter
@NoArgsConstructor
public class Repository {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "github_repo_full_name", nullable = false)
    private String githubRepoFullName;

    @Column(name = "github_repo_id")
    private Long githubRepoId;

    @Column(name = "webhook_id")
    private Long webhookId;

    @Column(name = "created_at", nullable = true, updatable = false)
    private Instant createdAt = Instant.now();
}
