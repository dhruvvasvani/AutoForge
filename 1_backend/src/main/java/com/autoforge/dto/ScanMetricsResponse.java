package com.autoforge.dto;

import java.time.Instant;
import java.util.Map;

public record ScanMetricsResponse(Long id, Instant scanTimestamp, Map<String, Object> metrics) {
}
