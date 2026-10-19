package com.autoforge.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateUserLimitRequest {
    @NotBlank(message = "planName is required")
    private String planName; // e.g. "FREE" or "PAID"
}
