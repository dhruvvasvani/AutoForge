package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class ScoredFindingDto {
    @JsonProperty("rule_id")
    @JsonAlias({"ruleId", "check_id"})
    private String ruleId;

    private String title;

    @JsonProperty("file_path")
    @JsonAlias({"filePath", "path", "file_abs_path"})
    private String filePath;

    @JsonProperty("line_number")
    @JsonAlias({"lineNumber"})
    private Integer lineNumber;

    private String severity;

    @JsonProperty("code_snippet")
    @JsonAlias({"codeSnippet", "code", "snippet"})
    private String codeSnippet;

    @JsonProperty("is_reachable")
    @JsonAlias({"isReachable", "reachable"})
    private Boolean reachable;

    @JsonProperty("reachability_status")
    @JsonAlias({"reachabilityStatus", "reachability_tag", "reachability"})
    private String reachabilityStatus;

    private String priority;

    @JsonProperty("ml_confidence_score")
    @JsonAlias({"mlConfidenceScore", "confidence"})
    private Double mlConfidenceScore;

    @JsonProperty("call_traces")
    @JsonAlias({"callTraces", "traces"})
    private List<CallTraceStepDto> callTraces;
}
