package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ScanSourceUploadResponse {
    @JsonProperty("scan_id")
    private Long scanId;

    @JsonProperty("project_id")
    private Long projectId;

    private String status;

    @JsonProperty("source_directory")
    private String sourceDirectory;
}
