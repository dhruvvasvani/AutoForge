package com.autoforge.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Instant;

@Getter
@AllArgsConstructor
public class PlanRequestResponse {
    private Long id;
    private Long userId;
    private String userEmail;
    private String requestedPlanName;
    private String status;
    private Instant createdAt;
}
