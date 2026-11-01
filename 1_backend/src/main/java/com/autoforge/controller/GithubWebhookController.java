package com.autoforge.controller;

import com.autoforge.service.ScanService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping({"/api/webhooks", "/api/v1/webhooks"})
@RequiredArgsConstructor
@Slf4j
public class GithubWebhookController {
    private final ScanService scanService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${autoforge.github.webhook-secret:change-this-in-env-vars}")
    private String webhookSecret;

    @Value("${autoforge.gitlab.webhook-secret:gitlab_webhook_secret_key}")
    private String gitlabSecret;

    @PostMapping("/github")
    public ResponseEntity<Map<String, Object>> handlePush(
            @RequestBody String rawPayload,
            @RequestHeader(value = "X-Hub-Signature-256", required = false) String signature,
            @RequestHeader(value = "X-GitHub-Event", required = false) String eventType
    ) throws Exception {
        Map<String, Object> response = new LinkedHashMap<>();

        if (signature == null || !isValidSignature(rawPayload, signature)) {
            response.put("status", "error");
            response.put("message", "Invalid or missing X-Hub-Signature-256 header");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        if (!"push".equals(eventType) && !"pull_request".equals(eventType)) {
            response.put("status", "ignored");
            response.put("message", "Ignored event type: " + eventType);
            return ResponseEntity.accepted().body(response);
        }

        JsonNode payload = objectMapper.readTree(rawPayload);
        String repoFullName = payload.path("repository").path("full_name").asText(null);
        JsonNode pullRequest = payload.path("pull_request");
        boolean pullRequestEvent = "pull_request".equals(eventType);
        String commitSha = pullRequestEvent
                ? pullRequest.path("head").path("sha").asText(null)
                : payload.path("after").asText(null);
        String branch = pullRequestEvent
                ? pullRequest.path("head").path("ref").asText(null)
                : branchFromRef(payload.path("ref").asText(null));
        if (branch == null || branch.isBlank()) {
            branch = "main";
        }
        if (!isSafeBranch(branch)) {
            response.put("status", "error");
            response.put("message", "Webhook branch name is invalid");
            return ResponseEntity.badRequest().body(response);
        }

        if (repoFullName == null || commitSha == null || commitSha.isBlank()) {
            response.put("status", "error");
            response.put("message", "Malformed push payload");
            return ResponseEntity.badRequest().body(response);
        }

        List<String> changedFiles = changedFiles(payload, pullRequestEvent);
        var scan = scanService.createScanJobFromPush(repoFullName, commitSha, eventType, branch, changedFiles);
        response.put("status", "accepted");
        response.put("message", "Scan job queued successfully");
        response.put("scan_id", scan.getId());
        response.put("branch", scan.getBranch());
        response.put("changed_files", changedFiles);
        return ResponseEntity.accepted().body(response);
    }

    @PostMapping("/gitlab")
    public ResponseEntity<Map<String, Object>> handleGitlab(
            @RequestBody String rawPayload,
            @RequestHeader(value = "X-Gitlab-Token", required = false) String gitlabToken,
            @RequestHeader(value = "X-Gitlab-Event", required = false) String eventType
    ) throws Exception {
        Map<String, Object> response = new LinkedHashMap<>();

        if (gitlabToken != null && !gitlabSecret.equals("gitlab_webhook_secret_key") && !gitlabSecret.equals(gitlabToken)) {
            response.put("status", "error");
            response.put("message", "Invalid X-Gitlab-Token header");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        JsonNode payload = objectMapper.readTree(rawPayload);
        String repoFullName = payload.path("project").path("path_with_namespace").asText(null);
        String commitSha = payload.path("after").asText(null);
        if (commitSha == null || commitSha.isBlank()) {
            commitSha = payload.path("checkout_sha").asText(null);
        }

        if (repoFullName == null || commitSha == null) {
            response.put("status", "error");
            response.put("message", "Malformed GitLab payload");
            return ResponseEntity.badRequest().body(response);
        }

        var scan = scanService.createScanJobFromPush(repoFullName, commitSha, eventType != null ? eventType : "push");
        response.put("status", "accepted");
        response.put("message", "GitLab scan job queued successfully");
        response.put("scan_id", scan.getId());
        return ResponseEntity.accepted().body(response);
    }

    private boolean isValidSignature(String payload, String signatureHeader) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(webhookSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] hash = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder("sha256=");
        for (byte b : hash) hex.append(String.format("%02x", b));
        return MessageDigest.isEqual(hex.toString().getBytes(StandardCharsets.UTF_8), signatureHeader.getBytes(StandardCharsets.UTF_8));
    }

    private String branchFromRef(String ref) {
        if (ref == null) return null;
        return ref.startsWith("refs/heads/") ? ref.substring("refs/heads/".length()) : ref;
    }

    private boolean isSafeBranch(String branch) {
        return branch.length() <= 64
                && branch.matches("[A-Za-z0-9._/-]+")
                && !branch.startsWith("-")
                && !branch.contains("..")
                && !branch.endsWith("/")
                && !branch.contains("//");
    }

    private List<String> changedFiles(JsonNode payload, boolean pullRequestEvent) {
        Set<String> paths = new LinkedHashSet<>();
        if (pullRequestEvent) {
            JsonNode files = payload.path("pull_request").path("files");
            if (files.isArray()) {
                for (JsonNode file : files) {
                    if (file.isTextual()) {
                        addSafePath(paths, file.asText());
                    } else {
                        addSafePath(paths, file.path("filename").asText(null));
                        addSafePath(paths, file.path("previous_filename").asText(null));
                    }
                }
            }
        } else {
            JsonNode commits = payload.path("commits");
            if (commits.isArray()) {
                for (JsonNode commit : commits) {
                    for (String changeType : List.of("added", "modified", "removed")) {
                        JsonNode files = commit.path(changeType);
                        if (files.isArray()) {
                            files.forEach(file -> addSafePath(paths, file.asText(null)));
                        }
                    }
                }
            }
        }
        return paths.stream().limit(500).toList();
    }

    private void addSafePath(Set<String> paths, String path) {
        if (path == null || path.isBlank() || path.length() > 1024
                || path.startsWith("/") || path.startsWith("\\")
                || path.matches("^[A-Za-z]:.*")
                || path.contains("\n") || path.contains("\r")) {
            return;
        }
        String normalized = path.replace('\\', '/');
        if (List.of(normalized.split("/")).contains("..")) {
            return;
        }
        paths.add(normalized);
    }
}
