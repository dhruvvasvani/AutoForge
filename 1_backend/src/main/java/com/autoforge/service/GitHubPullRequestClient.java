package com.autoforge.service;

import com.autoforge.exception.ApiException;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.ResourceAccessException;

import java.util.Map;

@Component
public class GitHubPullRequestClient {
    private final RestClient restClient;
    private final String token;

    public GitHubPullRequestClient(
            RestClient.Builder builder,
            @Value("${autoforge.github.api-url:https://api.github.com}") String apiUrl,
            @Value("${autoforge.github.token:}") String token
    ) {
        this.restClient = builder.baseUrl(apiUrl).build();
        this.token = token;
    }

    public PullRequestDetails createPullRequest(String repository, String base, String head, String title, String body) {
        if (token.isBlank()) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE,
                    "GitHub automation is not configured. Set GITHUB_TOKEN with repository contents and pull-request permissions.");
        }
        String[] parts = repository.split("/", -1);
        if (parts.length != 2 || !parts[0].matches("[A-Za-z0-9_.-]+")
                || !parts[1].matches("[A-Za-z0-9_.-]+")) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "A valid GitHub owner/repository is required.");
        }

        try {
            JsonNode response = restClient.post()
                    .uri("/repos/{owner}/{repo}/pulls", parts[0], parts[1])
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("title", title, "head", head, "base", base, "body", body))
                    .retrieve()
                    .body(JsonNode.class);
            JsonNode number = response == null ? null : response.get("number");
            JsonNode htmlUrl = response == null ? null : response.get("html_url");
            JsonNode state = response == null ? null : response.get("state");
            if (number == null || !number.canConvertToInt() || htmlUrl == null || !htmlUrl.isTextual()) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "GitHub returned an incomplete pull request response.");
            }
            return new PullRequestDetails(number.asInt(), htmlUrl.asText(),
                    state != null && state.isTextual() ? state.asText().toUpperCase() : "OPEN");
        } catch (RestClientResponseException ex) {
            throw new ApiException(ex.getStatusCode().value() == 422 ? HttpStatus.CONFLICT : HttpStatus.BAD_GATEWAY,
                    "GitHub pull request API returned HTTP " + ex.getStatusCode().value() + ".");
        } catch (ResourceAccessException ex) {
            throw new ApiException(HttpStatus.BAD_GATEWAY, "GitHub API could not be reached.");
        }
    }

    public record PullRequestDetails(int number, String url, String state) {
    }
}
