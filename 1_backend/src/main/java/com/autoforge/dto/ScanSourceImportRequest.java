package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScanSourceImportRequest {
    @NotBlank
    @JsonProperty("project_name")
    private String projectName;

    @NotBlank
    @JsonProperty("source_path")
    private String sourcePath;

    private String branch = "main";

    @JsonProperty("commit_sha")
    private String commitSha;
}
