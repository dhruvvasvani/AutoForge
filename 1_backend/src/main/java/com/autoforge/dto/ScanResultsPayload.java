package com.autoforge.dto;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScanResultsPayload {
    private String version = "v2.0";
    private Long scanId;
    private String repoFullName;
    private String commitSha;
    private String reachabilityTag;
    private Boolean isReachable;
    private String priority;
    private String mlPriority;
    private JsonNode semgrep;
    private JsonNode checkov;
    private JsonNode traces;
    private JsonNode modelOutputs;
}
