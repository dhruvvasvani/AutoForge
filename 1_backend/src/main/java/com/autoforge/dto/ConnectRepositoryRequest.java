package com.autoforge.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ConnectRepositoryRequest {
    @NotBlank(message = "githubRepoFullName is required, e.g. octocat/Hello-World")
    private String githubRepoFullName;
}
