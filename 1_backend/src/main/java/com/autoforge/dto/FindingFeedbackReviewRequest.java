package com.autoforge.dto;

import com.autoforge.entity.FindingFeedback;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FindingFeedbackReviewRequest {

    @NotNull
    private FindingFeedback.ReviewStatus status;
}
