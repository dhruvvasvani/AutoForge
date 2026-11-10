package com.autoforge.service;

import com.autoforge.exception.ApiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class GitHubPullRequestDispatchClient {
    private final RestClient restClient;
    private final String webhookUrl;

    public GitHubPullRequestDispatchClient(
            RestClient.Builder builder,
            @Value("${AUTOFORGE_GITHUB_PR_WEBHOOK_URL:}") String webhookUrl
    ) {
        this.webhookUrl = webhookUrl == null ? "" : webhookUrl.trim();
        this.restClient = this.webhookUrl.isEmpty() ? null : builder.build();
    }

    public String dispatch(String rawPayload, String signature) {
        if (webhookUrl.isEmpty()) {
            return "not_configured";
        }
        try {
            restClient.post()
                    .uri(webhookUrl)
                    .header("X-Hub-Signature-256", signature)
                    .header("X-GitHub-Event", "pull_request")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(rawPayload)
                    .retrieve()
                    .toBodilessEntity();
            return "queued";
        } catch (RestClientResponseException ex) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Pull-request analysis queue returned HTTP " + ex.getStatusCode().value() + ".");
        } catch (ResourceAccessException ex) {
            log.warn("Pull-request analysis queue is unavailable ({}); the dashboard scan remains queued.",
                    ex.getClass().getSimpleName());
            return "unavailable";
        }
    }

    public boolean isConfigured() {
        return !webhookUrl.isEmpty();
    }
}
