package com.autoforge;

import com.autoforge.config.RedisConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.autoforge.service.QueueService;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class QueueServiceTest {
    @Test
    @SuppressWarnings("unchecked")
    void claimsRedisJobsIntoProcessingQueueAndAcknowledgesThem() {
        RedisTemplate<String, Object> redis = mock(RedisTemplate.class);
        ListOperations<String, Object> lists = mock(ListOperations.class);
        when(redis.opsForList()).thenReturn(lists);
        Map<String, Object> payload = Map.of("job_id", "41", "repo_url", "https://github.com/acme/demo");
        when(lists.rightPopAndLeftPush(QueueService.SCAN_JOBS_QUEUE,
                QueueService.SCAN_JOBS_PROCESSING_QUEUE)).thenReturn(payload);
        QueueService queue = new QueueService();
        ReflectionTestUtils.setField(queue, "redisTemplate", redis);

        queue.publishScanJob(41L, 8L, "https://github.com/acme/demo", "deadbeef1", "main");
        verify(lists).rightPush(eq(QueueService.SCAN_JOBS_QUEUE), argThat(message ->
                message instanceof Map<?, ?> job
                        && job.get("job_id").equals("41")
                        && job.get("scan_id").equals(41L)
                        && job.get("project_id").equals(8L)
                        && job.get("repository_id").equals(8L)
                        && job.get("changed_files") instanceof java.util.List<?>));

        QueueService.ClaimedRedisJob claimed = queue.claimNextRedisJob();
        assertNotNull(claimed);
        assertSame(payload, claimed.rawPayload());
        assertEquals(payload, claimed.payload());

        queue.acknowledgeRedisJob(claimed);
        verify(lists).remove(QueueService.SCAN_JOBS_PROCESSING_QUEUE, 1, payload);
    }

    @Test
    @SuppressWarnings("unchecked")
    void redisQueueValuesAreReadableJson() throws Exception {
        RedisTemplate<String, Object> template = new RedisConfig().redisTemplate(
                mock(RedisConnectionFactory.class), new ObjectMapper());
        RedisSerializer<Object> serializer = (RedisSerializer<Object>) template.getValueSerializer();

        byte[] value = serializer.serialize(Map.of(
                "job_id", "41",
                "scan_id", 41L,
                "project_id", 8L,
                "repository_id", 8L,
                "repo_url", "https://github.com/acme/demo",
                "commit_sha", "deadbeef1",
                "branch", "main",
                "changed_files", java.util.List.of()));

        var json = new ObjectMapper().readTree(value);
        assertEquals(41L, json.path("scan_id").asLong());
        assertEquals("https://github.com/acme/demo", json.path("repo_url").asText());
    }

    @Test
    @SuppressWarnings("unchecked")
    void requeuesUnacknowledgedJobsAtStartup() {
        RedisTemplate<String, Object> redis = mock(RedisTemplate.class);
        ListOperations<String, Object> lists = mock(ListOperations.class);
        when(redis.opsForList()).thenReturn(lists);
        when(lists.rightPopAndLeftPush(QueueService.SCAN_JOBS_PROCESSING_QUEUE,
                QueueService.SCAN_JOBS_QUEUE)).thenReturn(Map.of("job_id", "41")).thenReturn(null);
        QueueService queue = new QueueService();
        ReflectionTestUtils.setField(queue, "redisTemplate", redis);

        queue.recoverProcessingJobs();

        verify(lists, times(2)).rightPopAndLeftPush(QueueService.SCAN_JOBS_PROCESSING_QUEUE,
                QueueService.SCAN_JOBS_QUEUE);
    }
}
