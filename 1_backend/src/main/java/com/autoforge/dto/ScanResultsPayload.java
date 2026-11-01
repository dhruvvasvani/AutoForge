package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanResultsPayload {
    private String version = "v2.0";
    private Long scanId;
    private String repoFullName;
    private String commitSha;
    private String status;
    private String error;
    private String reachabilityTag;
    private Boolean isReachable;
    private String priority;
    private String mlPriority;
    private JsonNode semgrep;
    private JsonNode checkov;
    @JsonProperty("tagged_findings")
    private JsonNode taggedFindings;
    private Double combinedRiskScore;
    private JsonNode traces;
    private JsonNode modelOutputs;
}
