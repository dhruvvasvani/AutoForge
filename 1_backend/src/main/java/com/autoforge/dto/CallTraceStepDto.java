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
public class CallTraceStepDto {
    @JsonProperty("step_number")
    private Integer stepNumber;

    @JsonProperty("file_path")
    private String filePath;

    @JsonProperty("line_number")
    private Integer lineNumber;

    @JsonProperty("symbol_name")
    private String symbolName;
}
