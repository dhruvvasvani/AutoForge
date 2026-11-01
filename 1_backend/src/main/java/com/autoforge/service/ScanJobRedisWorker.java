package com.autoforge.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class ScanJobRedisWorker {
    private final ScanExecutionService scanExecutionService;
    private final ScanService scanService;
    private final QueueService queueService;

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    public boolean processNextJob() {
        Map<String, Object> payload = null;
        QueueService.ClaimedRedisJob redisJob = null;
        try {
            if (redisTemplate != null) {
                redisJob = queueService.claimNextRedisJob();
                if (redisJob != null) payload = redisJob.payload();
            }
        } catch (Exception ex) {
            log.warn("Redis scan queue poll failed; checking the in-memory queue: {}", ex.getMessage());
        }

        if (payload == null) {
            payload = queueService.getFallbackQueue().poll();
        }
        if (payload == null) {
            return false;
        }

        Long scanId = parseLong(payload.get("job_id"), parseLong(payload.get("scan_id"), null));
        boolean safeToAcknowledge = scanId == null;
        try {
            if (scanId == null) {
                throw new IllegalArgumentException("Queued scan job is missing a valid job_id.");
            }
            String repositoryUrl = requiredString(payload, "repo_url");
            String commitSha = optionalString(payload.get("commit_sha"));
            String branch = optionalString(payload.get("branch"));
            scanExecutionService.startQueuedRepositoryScan(scanId, repositoryUrl, commitSha, branch);
            safeToAcknowledge = true;
            log.info("Queued repository scan {} handed to the background scanner.", scanId);
        } catch (RuntimeException ex) {
            log.error("Unable to start queued scan {}: {}", scanId, ex.getMessage(), ex);
            if (ex instanceof com.autoforge.exception.ApiException apiException
                    && apiException.getStatus() == org.springframework.http.HttpStatus.CONFLICT) {
                safeToAcknowledge = true;
            } else if (scanId != null) {
                try {
                    scanService.failQueuedScan(scanId, ex.getMessage());
                    safeToAcknowledge = true;
                } catch (RuntimeException updateFailure) {
                    log.error("Unable to record queued scan failure for {}: {}", scanId, updateFailure.getMessage(), updateFailure);
                }
            }
        }
        if (safeToAcknowledge && redisJob != null) {
            try {
                queueService.acknowledgeRedisJob(redisJob);
            } catch (RuntimeException ex) {
                log.error("Unable to acknowledge Redis scan job {}: {}", scanId, ex.getMessage(), ex);
            }
        }
        return true;
    }

    private String requiredString(Map<String, Object> payload, String key) {
        String value = optionalString(payload.get(key));
        if (value == null) {
            throw new IllegalArgumentException("Queued scan job is missing " + key + ".");
        }
        return value;
    }

    private String optionalString(Object value) {
        if (value == null) return null;
        String text = String.valueOf(value);
        return text.isBlank() || "null".equalsIgnoreCase(text) ? null : text;
    }

    private Long parseLong(Object value, Long fallback) {
        if (value instanceof Number number) return number.longValue();
        if (value == null) return fallback;
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }
}
