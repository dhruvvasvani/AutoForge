package com.autoforge.dto;

import com.autoforge.entity.FindingFeedback;

import java.time.Instant;

public record FindingFeedbackResponse(
        Long id,
        String findingKey,
        FindingFeedback.Label label,
        String sourceSnippet,
        String reason,
        FindingFeedback.ReviewStatus reviewStatus,
        String submittedBy,
        Instant createdAt,
        String reviewedBy,
        Instant reviewedAt,
        Instant trainedAt
) {
}
