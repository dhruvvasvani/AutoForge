package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RemediationPreviewResponse {
    @JsonProperty("finding_id")
    private Long findingId;

    @JsonProperty("file_path")
    private String filePath;

    @JsonProperty("line_number")
    private Integer lineNumber;

    @JsonProperty("original_snippet")
    private String originalSnippet;

    @JsonProperty("suggested_fix")
    private String suggestedFix;

    @JsonProperty("unified_diff")
    private String unifiedDiff;
}
