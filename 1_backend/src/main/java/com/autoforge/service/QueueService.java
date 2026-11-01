package com.autoforge.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

@Service
@Slf4j
@RequiredArgsConstructor
public class QueueService {
    public static final String SCAN_JOBS_QUEUE = "autoforge:scan_jobs";
    public static final String SCAN_JOBS_PROCESSING_QUEUE = "autoforge:scan_jobs:processing";

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    private final ConcurrentLinkedQueue<Map<String, Object>> fallbackQueue = new ConcurrentLinkedQueue<>();

    @EventListener(ApplicationReadyEvent.class)
    public void recoverProcessingJobs() {
        if (redisTemplate == null) {
            return;
        }
        try {
            Object recovered;
            int count = 0;
            while ((recovered = redisTemplate.opsForList()
                    .rightPopAndLeftPush(SCAN_JOBS_PROCESSING_QUEUE, SCAN_JOBS_QUEUE)) != null) {
                count++;
            }
            if (count > 0) {
                log.warn("Requeued {} unacknowledged scan jobs after application startup.", count);
            }
        } catch (Exception ex) {
            log.error("Unable to recover unacknowledged Redis scan jobs: {}", ex.getMessage(), ex);
        }
    }

    public ClaimedRedisJob claimNextRedisJob() {
        if (redisTemplate == null) {
            return null;
        }
        Object rawPayload = redisTemplate.opsForList()
                .rightPopAndLeftPush(SCAN_JOBS_QUEUE, SCAN_JOBS_PROCESSING_QUEUE);
        if (rawPayload == null) {
            return null;
        }
        if (!(rawPayload instanceof Map<?, ?> map)) {
            return new ClaimedRedisJob(rawPayload, Map.of());
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        map.forEach((key, value) -> payload.put(String.valueOf(key), value));
        return new ClaimedRedisJob(rawPayload, payload);
    }

    public void acknowledgeRedisJob(ClaimedRedisJob job) {
        if (redisTemplate != null && job != null) {
            redisTemplate.opsForList().remove(SCAN_JOBS_PROCESSING_QUEUE, 1, job.rawPayload());
        }
    }

    public void publishScanJob(Long scanId, Long projectId, String repoUrl, String commitSha, String branch) {
        publishScanJob(scanId, projectId, repoUrl, commitSha, branch, List.of());
    }

    public void publishScanJob(Long scanId, Long projectId, String repoUrl, String commitSha, String branch,
                               List<String> changedFiles) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("job_id", String.valueOf(scanId));
        payload.put("project_id", String.valueOf(projectId));
        payload.put("repo_url", repoUrl);
        payload.put("commit_sha", commitSha);
        payload.put("branch", branch != null ? branch : "main");
        payload.put("repository_id", projectId);
        payload.put("scan_id", scanId);
        payload.put("changed_files", changedFiles == null ? List.of() : List.copyOf(changedFiles));

        try {
            if (redisTemplate != null) {
                redisTemplate.opsForList().rightPush(SCAN_JOBS_QUEUE, payload);
                log.info("Successfully pushed scan job {} to Redis queue {}", scanId, SCAN_JOBS_QUEUE);
                return;
            }
        } catch (Exception e) {
            log.warn("Redis unavailable ({}); routed scan job {} to in-memory fallback queue.", e.getMessage(), scanId);
        }

        fallbackQueue.add(payload);
        log.info("Queued scan job {} in in-memory fallback queue. Current queue depth: {}", scanId, fallbackQueue.size());
    }

    public ConcurrentLinkedQueue<Map<String, Object>> getFallbackQueue() {
        return fallbackQueue;
    }

    public record ClaimedRedisJob(Object rawPayload, Map<String, Object> payload) {}
}
