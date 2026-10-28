package com.autoforge.service;

import com.autoforge.dto.ScanMetricsRequest;
import com.autoforge.dto.ScanMetricsResponse;
import com.autoforge.entity.ScanMetrics;
import com.autoforge.entity.User;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.ScanMetricsRepository;
import com.autoforge.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Transactional
public class ScanMetricsService {

    private static final int MAX_METRICS_BYTES = 262_144;
    private static final int MAX_HISTORY_LIMIT = 100;
    private static final Set<String> ALLOWED_FIELDS = Set.of(
            "scan_timestamp", "files_received", "files_analyzed", "ast_coverage_pct",
            "total_findings", "severity_counts", "reachable_findings", "unreachable_findings",
            "unverified_findings", "reachability", "noise_reduction_pct", "unreachable_noise_pct",
            "file_hotspots"
    );
    private static final List<String> REQUIRED_COUNTS = List.of(
            "files_received", "files_analyzed", "total_findings",
            "reachable_findings", "unreachable_findings", "unverified_findings"
    );

    private final ScanMetricsRepository scanMetricsRepository;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    public ScanMetricsResponse record(String email, ScanMetricsRequest request) {
        Map<String, Object> metrics = request.metrics();
        Instant scanTimestamp = validateMetrics(metrics);
        String metricsJson;
        try {
            metricsJson = objectMapper.writeValueAsString(metrics);
        } catch (JsonProcessingException error) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Scan metrics must be valid JSON");
        }
        if (metricsJson.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_METRICS_BYTES) {
            throw new ApiException(HttpStatus.PAYLOAD_TOO_LARGE, "Scan metrics exceed the 256 KB limit");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        ScanMetrics scanMetrics = new ScanMetrics();
        scanMetrics.setUser(user);
        scanMetrics.setScanTimestamp(scanTimestamp);
        scanMetrics.setMetricsJson(metricsJson);
        return toResponse(scanMetricsRepository.save(scanMetrics));
    }

    @Transactional(readOnly = true)
    public List<ScanMetricsResponse> history(String email, int limit) {
        if (limit < 1 || limit > MAX_HISTORY_LIMIT) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "limit must be between 1 and 100");
        }
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        return scanMetricsRepository.findRecentByUserId(user.getId(), PageRequest.of(0, limit))
                .stream()
                .map(this::toResponse)
                .toList();
    }

    private Instant validateMetrics(Map<String, Object> metrics) {
        if (metrics == null || metrics.isEmpty()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "metrics must be a non-empty object");
        }
        if (!ALLOWED_FIELDS.containsAll(metrics.keySet())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "metrics contains unsupported fields");
        }
        Object timestamp = metrics.get("scan_timestamp");
        if (!(timestamp instanceof String timestampText)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "metrics.scan_timestamp must be an ISO-8601 timestamp");
        }
        Instant scanTimestamp;
        try {
            scanTimestamp = Instant.parse(timestampText);
        } catch (DateTimeParseException error) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "metrics.scan_timestamp must be an ISO-8601 timestamp");
        }

        for (String field : REQUIRED_COUNTS) {
            Object value = metrics.get(field);
            if (!(value instanceof Number number) || number.longValue() < 0
                    || number.doubleValue() != number.longValue()) {
                throw new ApiException(HttpStatus.BAD_REQUEST, "metrics." + field + " must be a non-negative integer");
            }
        }
        long received = ((Number) metrics.get("files_received")).longValue();
        long analyzed = ((Number) metrics.get("files_analyzed")).longValue();
        if (analyzed > received) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "metrics.files_analyzed cannot exceed files_received");
        }
        return scanTimestamp;
    }

    private ScanMetricsResponse toResponse(ScanMetrics scanMetrics) {
        try {
            Map<String, Object> metrics = objectMapper.readValue(
                    scanMetrics.getMetricsJson(),
                    new TypeReference<>() { }
            );
            return new ScanMetricsResponse(
                    scanMetrics.getId(),
                    scanMetrics.getScanTimestamp(),
                    metrics
            );
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("Persisted scan metrics could not be decoded", error);
        }
    }
}
