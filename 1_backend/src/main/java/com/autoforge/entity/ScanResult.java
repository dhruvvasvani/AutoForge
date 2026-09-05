package com.autoforge.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;
import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import org.hibernate.annotations.Type;

/**
 * ScanResult: Represents a single security scan execution
 * Stores aggregated results from Semgrep/Checkov + AST analysis
 */
@Entity
@Table(name = "scan_results", indexes = {
    @Index(name = "idx_scan_results_repo", columnList = "repository_id"),
    @Index(name = "idx_scan_results_timestamp", columnList = "scan_timestamp"),
    @Index(name = "idx_scan_results_commit", columnList = "commit_hash")
})
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "repository_id", nullable = false)
    private Repository repository;

    @Column(nullable = false, length = 40)
    private String commitHash;

    @Column(length = 255)
    private String branch;

    @Column(name = "scan_timestamp")
    private LocalDateTime scanTimestamp;

    @Column(nullable = false)
    private Integer totalFindings = 0;

    @Column(nullable = false)
    private Integer reachableFindings = 0;

    @Column(nullable = false)
    private Integer unreachableFindings = 0;

    @Column(name = "p0_count", nullable = false)
    private Integer p0Count = 0;

    @Column(name = "p1_count", nullable = false)
    private Integer p1Count = 0;

    @Column(name = "p2_count", nullable = false)
    private Integer p2Count = 0;

    @Column(name = "p3_count", nullable = false)
    private Integer p3Count = 0;

    /**
     * Raw scanner output (Semgrep + Checkov JSON)
     */
    @Type(JsonBinaryType.class)
    @Column(columnDefinition = "jsonb")
    private String rawResults;

    /**
     * Filtered results after AST reachability analysis
     */
    @Type(JsonBinaryType.class)
    @Column(columnDefinition = "jsonb")
    private String filteredResults;

    /**
     * Scored results with P0-P3 priorities
     */
    @Type(JsonBinaryType.class)
    @Column(columnDefinition = "jsonb")
    private String scoredResults;

    @Column(length = 50)
    private String status = "PENDING"; // PENDING, PROCESSING, COMPLETED, FAILED

    @Column(columnDefinition = "TEXT")
    private String errorMessage;

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Finding> findings;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        scanTimestamp = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Repository getRepository() {
        return repository;
    }

    public void setRepository(Repository repository) {
        this.repository = repository;
    }

    public String getCommitHash() {
        return commitHash;
    }

    public void setCommitHash(String commitHash) {
        this.commitHash = commitHash;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public LocalDateTime getScanTimestamp() {
        return scanTimestamp;
    }

    public void setScanTimestamp(LocalDateTime scanTimestamp) {
        this.scanTimestamp = scanTimestamp;
    }

    public Integer getTotalFindings() {
        return totalFindings;
    }

    public void setTotalFindings(Integer totalFindings) {
        this.totalFindings = totalFindings;
    }

    public Integer getReachableFindings() {
        return reachableFindings;
    }

    public void setReachableFindings(Integer reachableFindings) {
        this.reachableFindings = reachableFindings;
    }

    public Integer getUnreachableFindings() {
        return unreachableFindings;
    }

    public void setUnreachableFindings(Integer unreachableFindings) {
        this.unreachableFindings = unreachableFindings;
    }

    public Integer getP0Count() {
        return p0Count;
    }

    public void setP0Count(Integer p0Count) {
        this.p0Count = p0Count;
    }

    public Integer getP1Count() {
        return p1Count;
    }

    public void setP1Count(Integer p1Count) {
        this.p1Count = p1Count;
    }

    public Integer getP2Count() {
        return p2Count;
    }

    public void setP2Count(Integer p2Count) {
        this.p2Count = p2Count;
    }

    public Integer getP3Count() {
        return p3Count;
    }

    public void setP3Count(Integer p3Count) {
        this.p3Count = p3Count;
    }

    public String getRawResults() {
        return rawResults;
    }

    public void setRawResults(String rawResults) {
        this.rawResults = rawResults;
    }

    public String getFilteredResults() {
        return filteredResults;
    }

    public void setFilteredResults(String filteredResults) {
        this.filteredResults = filteredResults;
    }

    public String getScoredResults() {
        return scoredResults;
    }

    public void setScoredResults(String scoredResults) {
        this.scoredResults = scoredResults;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public void setFindings(List<Finding> findings) {
        this.findings = findings;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    @Override
    public String toString() {
        return "ScanResult{" +
                "id=" + id +
                ", commitHash='" + commitHash + '\'' +
                ", totalFindings=" + totalFindings +
                ", reachableFindings=" + reachableFindings +
                ", unreachableFindings=" + unreachableFindings +
                ", status='" + status + '\'' +
                ", createdAt=" + createdAt +
                '}';
    }
}
