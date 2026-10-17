package com.autoforge.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateScanRequest {
    @NotBlank
    private String repoFullName;
    @NotBlank
    private String commitSha;
}
