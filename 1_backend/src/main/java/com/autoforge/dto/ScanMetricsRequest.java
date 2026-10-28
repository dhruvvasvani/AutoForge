package com.autoforge.dto;

import jakarta.validation.constraints.NotNull;

import java.util.Map;

public record ScanMetricsRequest(@NotNull Map<String, Object> metrics) {
}
