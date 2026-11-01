package com.autoforge.service;

import com.autoforge.exception.ApiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.util.Map;

@Component
public class GitHubCommitStatusClient {
    private final RestClient restClient;
    private final String token;

    public GitHubCommitStatusClient(
            RestClient.Builder builder,
            @Value("${autoforge.github.api-url:https://api.github.com}") String apiUrl,
            @Value("${autoforge.github.token:}") String token
    ) {
        this.restClient = builder.baseUrl(apiUrl).build();
        this.token = token;
    }

    public void publish(String repository, String commitSha, boolean passed, String description) {
        if (token.isBlank()) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE,
                    "GitHub quality status is not configured. Set GITHUB_TOKEN with commit status permissions.");
        }
        String[] parts = repository.split("/", -1);
        if (parts.length != 2 || !parts[0].matches("[A-Za-z0-9_.-]+")
                || !parts[1].matches("[A-Za-z0-9_.-]+")
                || commitSha == null || !commitSha.matches("[a-fA-F0-9]{7,64}")) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "A valid GitHub repository and commit SHA are required to publish a quality status.");
        }

        try {
            restClient.post()
                    .uri("/repos/{owner}/{repo}/statuses/{sha}", parts[0], parts[1], commitSha)
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of(
                            "state", passed ? "success" : "failure",
                            "context", "AutoForge/quality-gate",
                            "description", description.substring(0, Math.min(description.length(), 140))))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientResponseException ex) {
            throw new ApiException(HttpStatus.BAD_GATEWAY,
                    "GitHub commit status API returned HTTP " + ex.getStatusCode().value() + ".");
        } catch (ResourceAccessException ex) {
            throw new ApiException(HttpStatus.BAD_GATEWAY, "GitHub API could not be reached.");
        }
    }
}
