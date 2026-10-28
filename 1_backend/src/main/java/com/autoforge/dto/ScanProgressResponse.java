package com.autoforge.dto;

import java.time.Instant;

public record ScanProgressResponse(
        Long id,
        String status,
        String progressStage,
        String progressMessage,
        String commitSha,
        Instant createdAt,
        Instant startedAt,
        Instant completedAt
) {
}
