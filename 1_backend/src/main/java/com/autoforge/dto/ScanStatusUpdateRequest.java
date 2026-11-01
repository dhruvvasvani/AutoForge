package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScanStatusUpdateRequest {
    @JsonProperty("status")
    private String status;

    @JsonProperty("error_message")
    private String errorMessage;
}
