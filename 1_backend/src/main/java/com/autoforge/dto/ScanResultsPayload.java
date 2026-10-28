package com.autoforge.dto;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScanResultsPayload {
    private String repoFullName;
    private String commitSha;
    private JsonNode semgrep; // raw Semgrep findings array
    private JsonNode checkov; // raw Checkov failed_checks array
    private JsonNode ast;
    private JsonNode taggedFindings;
    private Double combinedRiskScore;
}
