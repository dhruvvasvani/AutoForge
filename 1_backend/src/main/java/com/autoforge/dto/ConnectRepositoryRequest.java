package com.autoforge.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ConnectRepositoryRequest {
    @NotBlank(message = "githubRepoFullName is required, e.g. octocat/Hello-World")
    @Pattern(
            regexp = "^[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*$",
            message = "githubRepoFullName must use the owner/repository format"
    )
    private String githubRepoFullName;
}
