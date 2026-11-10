package com.autoforge.service;

import com.autoforge.exception.ApiException;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class GitHubRepositoryClient {
    private static final Pattern HEAD_BRANCH = Pattern.compile("^ref: refs/heads/(.+)\\tHEAD$");
    private static final Pattern HEAD_SHA = Pattern.compile("^([a-fA-F0-9]{40})\\tHEAD$");

    private final RestClient restClient;
    private final String token;

    public GitHubRepositoryClient(
            RestClient.Builder builder,
            @Value("${autoforge.github.api-url:https://api.github.com}") String apiUrl,
            @Value("${autoforge.github.token:}") String token
    ) {
        this.restClient = builder.baseUrl(apiUrl).build();
        this.token = token;
    }

    public LatestCommit latestCommit(String repository) {
        String[] parts = repository.split("/", -1);
        if (parts.length != 2 || !parts[0].matches("[A-Za-z0-9_.-]+")
                || !parts[1].matches("[A-Za-z0-9_.-]+")) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "A valid GitHub repository name is required.");
        }

        try {
            JsonNode metadata = request("/repos/{owner}/{repo}", parts[0], parts[1]);
            String branch = metadata.path("default_branch").asText(null);
            if (branch == null || branch.isBlank()) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "GitHub did not return a default branch.");
            }
            JsonNode commit = request("/repos/{owner}/{repo}/commits/{branch}", parts[0], parts[1], branch);
            String sha = commit.path("sha").asText(null);
            if (sha == null || !sha.matches("[a-fA-F0-9]{7,64}")) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "GitHub did not return a valid commit SHA.");
            }
            return new LatestCommit(branch, sha);
        } catch (RestClientResponseException ex) {
            if (ex.getStatusCode().value() == 404) {
                return latestCommitFromGit(repository);
            }
            throw new ApiException(HttpStatus.BAD_GATEWAY,
                    "GitHub API returned HTTP " + ex.getStatusCode().value() + ".");
        } catch (ResourceAccessException ex) {
            throw new ApiException(HttpStatus.BAD_GATEWAY, "GitHub API could not be reached.");
        }
    }

    static LatestCommit parseGitHead(String output) {
        String branch = null;
        String sha = null;
        for (String line : output.split("\\R")) {
            Matcher branchMatcher = HEAD_BRANCH.matcher(line);
            Matcher shaMatcher = HEAD_SHA.matcher(line);
            if (branchMatcher.matches()) {
                branch = branchMatcher.group(1);
            } else if (shaMatcher.matches()) {
                sha = shaMatcher.group(1);
            }
        }
        if (branch == null || sha == null) {
            throw new ApiException(HttpStatus.NOT_FOUND,
                    "GitHub repository was not found or has no readable default branch.");
        }
        return new LatestCommit(branch, sha);
    }

    private LatestCommit latestCommitFromGit(String repository) {
        Process process = null;
        try {
            process = new ProcessBuilder(
                    "git", "ls-remote", "--symref",
                    "https://github.com/" + repository + ".git", "HEAD")
                    .redirectErrorStream(true)
                    .start();
            if (!process.waitFor(15, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new ApiException(HttpStatus.GATEWAY_TIMEOUT,
                        "Timed out while checking the public GitHub repository.");
            }
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (process.exitValue() != 0) {
                throw new ApiException(HttpStatus.NOT_FOUND,
                        "GitHub repository was not found or is not publicly readable. Configure GITHUB_TOKEN for private repositories.");
            }
            return parseGitHead(output);
        } catch (IOException ex) {
            throw new ApiException(HttpStatus.BAD_GATEWAY,
                    "Could not check the repository through GitHub API or Git.");
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new ApiException(HttpStatus.BAD_GATEWAY,
                    "The GitHub repository check was interrupted.");
        }
    }

    private JsonNode request(String path, Object... uriVariables) {
        var request = restClient.get()
                .uri(path, uriVariables)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28");
        if (!token.isBlank()) {
            request.header("Authorization", "Bearer " + token);
        }
        return request.retrieve().body(JsonNode.class);
    }

    public record LatestCommit(String branch, String sha) {}
}
