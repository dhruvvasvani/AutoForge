package com.autoforge;

import com.autoforge.controller.GithubWebhookController;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.service.ScanService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class WebhookSecurityUnitTest {

    @Mock
    private ScanService scanService;

    private GithubWebhookController webhookController;

    private static final String SECRET = "test-webhook-secret-key-123";

    @BeforeEach
    void setUp() {
        webhookController = new GithubWebhookController(scanService);
        ReflectionTestUtils.setField(webhookController, "webhookSecret", SECRET);
        ReflectionTestUtils.setField(webhookController, "gitlabSecret", "test-gitlab-secret");
    }

    private String calculateHmac(String data, String key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKey);
        byte[] raw = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder("sha256=");
        for (byte b : raw) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Test
    void testValidGithubPushCreatesScan() throws Exception {
        String payload = """
                {
                  "repository": { "full_name": "octocat/Hello-World" },
                  "after": "6dcb09b5b57875f334f61aebed695e2e4193db5e",
                  "ref": "refs/heads/feature/security",
                  "commits": [
                    { "added": ["src/New.java"], "modified": ["src/Changed.java"], "removed": ["src/Old.java"] }
                  ]
                }
                """;
        String signature = calculateHmac(payload, SECRET);

        Scan scan = new Scan();
        scan.setId(10L);
        scan.setBranch("feature/security");
        scan.setStatus(ScanStatus.QUEUED);
        List<String> changedFiles = List.of("src/New.java", "src/Changed.java", "src/Old.java");
        when(scanService.createScanJobFromPush("octocat/Hello-World",
                "6dcb09b5b57875f334f61aebed695e2e4193db5e", "push", "feature/security", changedFiles))
                .thenReturn(scan);

        ResponseEntity<Map<String, Object>> response = webhookController.handlePush(payload, signature, "push");
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertEquals("accepted", response.getBody().get("status"));
        assertEquals(10L, response.getBody().get("scan_id"));
        assertEquals("feature/security", response.getBody().get("branch"));
        assertEquals(changedFiles, response.getBody().get("changed_files"));
        verify(scanService).createScanJobFromPush("octocat/Hello-World",
                "6dcb09b5b57875f334f61aebed695e2e4193db5e", "push", "feature/security", changedFiles);
    }

    @Test
    void testInvalidSignatureRejectedWithUnauthorized() throws Exception {
        String payload = "{\"repository\":{\"full_name\":\"test/repo\"}}";
        String badSignature = "sha256=invalidhexsignature0000000000000000000000000000000000000000000000";

        ResponseEntity<Map<String, Object>> response = webhookController.handlePush(payload, badSignature, "push");
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("error", response.getBody().get("status"));
        verify(scanService, never()).createScanJobFromPush(anyString(), anyString(), anyString());
    }

    @Test
    void testGitLabWebhookValidToken() throws Exception {
        String payload = """
                {
                  "project": { "path_with_namespace": "gitlab-org/gitlab" },
                  "after": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7"
                }
                """;

        Scan scan = new Scan();
        scan.setId(22L);
        when(scanService.createScanJobFromPush("gitlab-org/gitlab", "da1560886d4f094c3e6c9ef40349f7d38b5d27d7", "Push Hook"))
                .thenReturn(scan);

        ResponseEntity<Map<String, Object>> response = webhookController.handleGitlab(payload, "test-gitlab-secret", "Push Hook");
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertEquals(22L, response.getBody().get("scan_id"));
    }

    @Test
    void testGitLabWebhookInvalidTokenRejected() throws Exception {
        String payload = "{\"project\":{\"path_with_namespace\":\"gitlab-org/gitlab\"}}";
        ResponseEntity<Map<String, Object>> response = webhookController.handleGitlab(payload, "wrong-token", "Push Hook");
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }
}
