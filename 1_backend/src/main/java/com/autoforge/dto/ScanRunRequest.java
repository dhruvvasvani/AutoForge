package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScanRunRequest {
    @NotNull
    @JsonProperty("scan_id")
    private Long scanId;
}
