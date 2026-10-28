package com.autoforge.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ScanProgressRequest(
        @NotBlank @Size(max = 80) String stage,
        @Size(max = 500) String message,
        @Size(max = 20) String status
) {
}
