package com.autoforge.dto;

import java.time.Instant;

public record ScanFindingResponse(
        Long id,
        String sourceScanner,
        String filePath,
        Integer lineNumber,
        String ruleId,
        String severity,
        Boolean reachable,
        Double combinedRiskScore,
        String priority,
        String status,
        String description,
        Instant createdAt
) {
}
