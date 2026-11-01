package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FindingResponseDto {
    @JsonProperty("id")
    private Long id;

    @JsonProperty("scan_id")
    private Long scanId;

    @JsonProperty("rule_id")
    private String ruleId;

    @JsonProperty("title")
    private String title;

    @JsonProperty("file_path")
    private String filePath;

    @JsonProperty("line_number")
    private Integer lineNumber;

    @JsonProperty("severity")
    private String severity;

    @JsonProperty("code_snippet")
    private String codeSnippet;

    @JsonProperty("call_traces")
    @Builder.Default
    private List<CallTraceStepDto> callTraces = new ArrayList<>();
}
