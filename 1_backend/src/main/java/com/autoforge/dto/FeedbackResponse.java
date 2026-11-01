package com.autoforge.dto;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

@Getter
@Builder
public class FeedbackResponse {
    private Long id;
    private Long findingId;
    private Long fixId;
    private String action;
    private String comment;
    private Instant createdAt;
}
