package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProjectCreateRequest {
    @NotBlank
    @JsonProperty("name")
    private String name;

    @NotBlank
    @JsonProperty("repo_url")
    private String repoUrl;

    @JsonProperty("default_branch")
    private String defaultBranch = "main";
}
