package com.autoforge.controller;

import com.autoforge.service.ScanService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Week 10 deliverable: receives GitHub push webhooks, verifies the
 * X-Hub-Signature-256 header against autoforge.github.webhook-secret,
 * then hands the payload off to ScanService (Week 9) to persist a
 * WebhookEvent + QUEUED Scan row.
 *
 * NOTE: 2_pipeline's Express webhook is the primary receiver for the
 * async scan-job queue; this endpoint is the Java-side mirror used for
 * DB bookkeeping and is safe to call directly for local/manual testing.
 */
@RestController
@RequestMapping("/api/webhooks")
@RequiredArgsConstructor
public class GithubWebhookController {

    private final ScanService scanService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${autoforge.github.webhook-secret}")
    private String webhookSecret;

    @PostMapping("/github")
    public ResponseEntity<String> handlePush(
            @RequestBody String rawPayload,
            @RequestHeader(value = "X-Hub-Signature-256", required = false) String signature,
            @RequestHeader(value = "X-GitHub-Event", required = false) String eventType
    ) throws Exception {
        if (signature == null || !isValidSignature(rawPayload, signature)) {
            return ResponseEntity.status(401).body("Invalid or missing X-Hub-Signature-256 header");
        }

        if (!"push".equals(eventType)) {
            return ResponseEntity.accepted().body("Ignored event type: " + eventType);
        }

        JsonNode payload = objectMapper.readTree(rawPayload);
        String repoFullName = payload.path("repository").path("full_name").asText(null);
        String commitSha = payload.path("after").asText(null);

        if (repoFullName == null || commitSha == null) {
            return ResponseEntity.badRequest().body("Malformed push payload");
        }

        var scan = scanService.createScanJobFromPush(repoFullName, commitSha, eventType);

        return ResponseEntity.accepted().body("Scan job created: id=" + scan.getId());
    }

    private boolean isValidSignature(String payload, String signatureHeader) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(webhookSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] hash = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));

        StringBuilder hex = new StringBuilder("sha256=");
        for (byte b : hash) hex.append(String.format("%02x", b));

        return MessageDigest.isEqual(
                hex.toString().getBytes(StandardCharsets.UTF_8),
                signatureHeader.getBytes(StandardCharsets.UTF_8)
        );
    }
}
