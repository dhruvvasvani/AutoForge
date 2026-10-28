package com.autoforge.dto;

import com.autoforge.entity.FindingFeedback;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FindingFeedbackRequest {

    @NotBlank
    @Size(max = 256)
    private String findingKey;

    @NotNull
    private FindingFeedback.Label label;

    @NotBlank
    @Size(max = 16000)
    private String sourceSnippet;

    @Size(max = 2000)
    private String reason = "";
}
