package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScanProgressUpdateRequest {
    @NotBlank
    @Size(max = 64)
    @JsonProperty("stage")
    private String stage;

    @Size(max = 2048)
    @JsonProperty("message")
    private String message;
}
