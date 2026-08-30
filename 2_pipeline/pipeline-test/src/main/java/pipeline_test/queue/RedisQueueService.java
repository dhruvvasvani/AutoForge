package pipeline_test.queue;

import org.springframework.stereotype.Service;
import redis.clients.jedis.Jedis;

import java.util.UUID;

@Service
public class RedisQueueService {

    private static final String QUEUE_NAME = "scan_jobs";
    private static final String REDIS_HOST = "localhost";
    private static final int REDIS_PORT = 6379;

    public String pushScanJob(String repoName, String commitSha, String branch) {
        String scanId = UUID.randomUUID().toString();

        // Simple JSON string banao (Jackson use kar sakte ho better ke liye)
        String job = String.format(
                "{\"scan_id\":\"%s\",\"repo\":\"%s\",\"commit\":\"%s\",\"branch\":\"%s\",\"status\":\"PENDING\"}",
                scanId, repoName, commitSha, branch
        );

        try (Jedis jedis = new Jedis(REDIS_HOST, REDIS_PORT)) {
            jedis.rpush(QUEUE_NAME, job);
            System.out.println("Job pushed to Redis: " + job);
        }

        return scanId;
    }
}