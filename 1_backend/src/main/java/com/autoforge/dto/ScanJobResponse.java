package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanJobResponse {
    @JsonProperty("id")
    private Long id;

    @JsonProperty("job_id")
    public Long getJobId() {
        return id;
    }

    @JsonProperty("project_id")
    private Long projectId;

    @JsonProperty("commit_sha")
    private String commitSha;

    @JsonProperty("branch")
    private String branch;

    @JsonProperty("changed_files")
    private List<String> changedFiles;

    @JsonProperty("status")
    private String status;

    @JsonProperty("error_message")
    private String errorMessage;

    @JsonProperty("progress")
    private Integer progress;

    @JsonProperty("created_at")
    private Instant createdAt;

    @JsonProperty("completed_at")
    private Instant completedAt;
}
