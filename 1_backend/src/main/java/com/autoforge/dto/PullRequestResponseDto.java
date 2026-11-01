package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PullRequestResponseDto {
    @JsonProperty("id")
    private Long id;

    @JsonProperty("fix_id")
    private Long fixId;

    @JsonProperty("github_pr_number")
    private Integer githubPrNumber;

    @JsonProperty("github_pr_url")
    private String githubPrUrl;

    @JsonProperty("branch_name")
    private String branchName;

    @JsonProperty("status")
    private String status;

    @JsonProperty("created_at")
    private Instant createdAt;
}
