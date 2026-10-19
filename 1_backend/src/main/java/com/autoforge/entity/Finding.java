package com.autoforge.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Finding: Individual vulnerability finding from security scanners
 * Linked to a ScanResult and enriched with reachability information
 */
@Entity
@Table(name = "findings", indexes = {
    @Index(name = "idx_findings_scan", columnList = "scan_id"),
    @Index(name = "idx_findings_rule", columnList = "rule_id"),
    @Index(name = "idx_findings_file", columnList = "file_path"),
    @Index(name = "idx_findings_priority", columnList = "priority"),
    @Index(name = "idx_findings_reachability", columnList = "reachability")
})
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id", nullable = false)
    private ScanResult scan;

    @Column(nullable = false, length = 255)
    private String ruleId;

    @Column(nullable = false, length = 1024)
    private String filePath;

    private Integer lineNumber;

    @Column(length = 50)
    private String severity; // CRITICAL, HIGH, MEDIUM, LOW, INFO

    @Column(columnDefinition = "TEXT")
    private String message;

    @Column(columnDefinition = "TEXT")
    private String codeSnippet;

    @Column(length = 255)
    private String functionName;

    /**
     * Reachability from main(): REACHABLE_CODE or UNREACHABLE_NOISE
     */
    @Column(length = 50)
    private String reachability = "REACHABLE_CODE";

    /**
     * Priority: P0 (Critical), P1 (High), P2 (Medium), P3 (Low)
     */
    @Column(length = 10)
    private String priority;

    /**
     * Is this finding actionable (reachable)?
     */
    @Column(nullable = false)
    private Boolean isActionable = true;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
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

    public ScanResult getScan() {
        return scan;
    }

    public void setScan(ScanResult scan) {
        this.scan = scan;
    }

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public Integer getLineNumber() {
        return lineNumber;
    }

    public void setLineNumber(Integer lineNumber) {
        this.lineNumber = lineNumber;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getCodeSnippet() {
        return codeSnippet;
    }

    public void setCodeSnippet(String codeSnippet) {
        this.codeSnippet = codeSnippet;
    }

    public String getFunctionName() {
        return functionName;
    }

    public void setFunctionName(String functionName) {
        this.functionName = functionName;
    }

    public String getReachability() {
        return reachability;
    }

    public void setReachability(String reachability) {
        this.reachability = reachability;
    }

    public String getPriority() {
        return priority;
    }

    public void setPriority(String priority) {
        this.priority = priority;
    }

    public Boolean getIsActionable() {
        return isActionable;
    }

    public void setIsActionable(Boolean isActionable) {
        this.isActionable = isActionable;
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
        return "Finding{" +
                "id=" + id +
                ", ruleId='" + ruleId + '\'' +
                ", filePath='" + filePath + '\'' +
                ", lineNumber=" + lineNumber +
                ", severity='" + severity + '\'' +
                ", priority='" + priority + '\'' +
                ", reachability='" + reachability + '\'' +
                ", isActionable=" + isActionable +
                '}';
    }
}
