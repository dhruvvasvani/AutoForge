package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScanTriggerRequest {
    @NotNull
    @JsonProperty("project_id")
    private Long projectId;

    @NotBlank
    @JsonProperty("commit_sha")
    private String commitSha;

    @JsonProperty("branch")
    private String branch = "main";

    @JsonProperty("idempotency_key")
    private String idempotencyKey;
}
