package com.autoforge.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "pull_requests")
@Getter
@Setter
@NoArgsConstructor
public class PullRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "fix_id", nullable = false)
    private Fix fix;

    @Column(name = "github_pr_number")
    private Integer githubPrNumber;

    @Column(name = "github_pr_url")
    private String githubPrUrl;

    @Column(name = "branch_name")
    private String branchName;

    @Column(nullable = false, length = 20)
    private String status = "OPEN";

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();
}
