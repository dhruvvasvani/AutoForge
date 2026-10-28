package com.autoforge.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import java.util.List;

public record MarkFeedbackTrainedRequest(
        @NotEmpty
        @Size(max = 1000)
        List<@Positive Long> feedbackIds
) {
}
