package com.autoforge;

import com.autoforge.service.QueueService;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.RedisTemplate;
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

        QueueService.ClaimedRedisJob claimed = queue.claimNextRedisJob();
        assertNotNull(claimed);
        assertSame(payload, claimed.rawPayload());
        assertEquals(payload, claimed.payload());

        queue.acknowledgeRedisJob(claimed);
        verify(lists).remove(QueueService.SCAN_JOBS_PROCESSING_QUEUE, 1, payload);
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
