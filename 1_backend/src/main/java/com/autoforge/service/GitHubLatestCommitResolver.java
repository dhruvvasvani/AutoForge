package com.autoforge.service;

import com.autoforge.exception.ApiException;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.util.regex.Pattern;

@Component
public class GitHubLatestCommitResolver {

    private static final Pattern REPOSITORY_NAME = Pattern.compile(
            "^[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*$"
    );

    private final RestClient client;

    public GitHubLatestCommitResolver(RestClient.Builder builder) {
        this.client = builder
                .baseUrl("https://api.github.com")
                .defaultHeader("Accept", "application/vnd.github+json")
                .defaultHeader("X-GitHub-Api-Version", "2022-11-28")
                .build();
    }

    public String resolve(String repositoryFullName) {
        if (repositoryFullName == null || !REPOSITORY_NAME.matcher(repositoryFullName).matches()
                || ".".equals(owner(repositoryFullName)) || "..".equals(owner(repositoryFullName))
                || ".".equals(name(repositoryFullName)) || "..".equals(name(repositoryFullName))) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Repository must use the owner/repository format");
        }

        try {
            JsonNode repository = client.get()
                    .uri("/repos/{owner}/{repo}", owner(repositoryFullName), name(repositoryFullName))
                    .retrieve()
                    .body(JsonNode.class);
            String branch = repository == null ? null : repository.path("default_branch").asText(null);
            if (branch == null || branch.isBlank()) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "GitHub did not return a default branch");
            }

            JsonNode commits = client.get()
                    .uri(uriBuilder -> uriBuilder
                            .path("/repos/{owner}/{repo}/commits")
                            .queryParam("sha", "{branch}")
                            .queryParam("per_page", 1)
                            .build(owner(repositoryFullName), name(repositoryFullName), branch))
                    .retrieve()
                    .body(JsonNode.class);
            String commitSha = commits == null || !commits.isArray() || commits.isEmpty()
                    ? null
                    : commits.get(0).path("sha").asText(null);
            if (commitSha == null || !commitSha.matches("(?i)^[0-9a-f]{40}$")) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "GitHub did not return a valid commit for the default branch");
            }
            return commitSha;
        } catch (RestClientResponseException error) {
            if (error.getStatusCode().value() == 404) {
                throw new ApiException(
                        HttpStatus.NOT_FOUND,
                        "GitHub repository is not publicly accessible; private repositories need configured server-side GitHub credentials"
                );
            }
            if (error.getStatusCode().value() == 403 || error.getStatusCode().value() == 429) {
                throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "GitHub API rate limit or access policy prevented the scan");
            }
            throw new ApiException(HttpStatus.BAD_GATEWAY, "GitHub could not resolve the repository's latest commit");
        } catch (ResourceAccessException error) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "Could not reach the GitHub API");
        }
    }

    private static String owner(String repositoryFullName) {
        return repositoryFullName.substring(0, repositoryFullName.indexOf('/'));
    }

    private static String name(String repositoryFullName) {
        return repositoryFullName.substring(repositoryFullName.indexOf('/') + 1);
    }
}
