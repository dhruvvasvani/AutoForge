package com.autoforge.service;

import com.autoforge.entity.Fix;
import com.autoforge.entity.Scan;
import com.autoforge.exception.ApiException;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.PushResult;
import org.eclipse.jgit.transport.RemoteRefUpdate;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;

@Component
@Slf4j
public class GitHubPatchPublisher {
    private final GitHubPullRequestClient pullRequestClient;
    private final String token;

    public GitHubPatchPublisher(
            GitHubPullRequestClient pullRequestClient,
            @Value("${autoforge.github.token:}") String token
    ) {
        this.pullRequestClient = pullRequestClient;
        this.token = token;
    }

    public PublishedPullRequest publish(Fix fix) {
        if (token.isBlank()) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE,
                    "GitHub automation is not configured. Set GITHUB_TOKEN with repository contents and pull-request permissions.");
        }
        if (fix.getFinding() == null || fix.getFinding().getScan() == null || fix.getSuggestedPatch() == null) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "The approved fix is missing its scan or patch.");
        }
        String repositorySlug = repositorySlug(fix.getFinding().getScan());
        String baseBranch = branchName(fix.getFinding().getScan().getBranch());
        String filePath = validatePatch(fix);
        String branchName = "security/autoforge-fix-" + fix.getId();

        Path workspace;
        try {
            workspace = Files.createTempDirectory("autoforge-fix-" + fix.getId() + "-");
        } catch (IOException ex) {
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, "Unable to create a temporary Git workspace.");
        }

        try {
            UsernamePasswordCredentialsProvider credentials =
                    new UsernamePasswordCredentialsProvider("x-access-token", token);
            try (Git git = Git.cloneRepository()
                    .setURI("https://github.com/" + repositorySlug + ".git")
                    .setDirectory(workspace.toFile())
                    .setBranch(baseBranch)
                    .setDepth(1)
                    .setCredentialsProvider(credentials)
                    .call()) {
                git.checkout().setCreateBranch(true).setName(branchName).call();
                git.apply().setPatch(new ByteArrayInputStream(
                        fix.getSuggestedPatch().getBytes(StandardCharsets.UTF_8))).call();

                var status = git.status().call();
                if (!status.getChanged().equals(java.util.Set.of(filePath))
                        || !status.getAdded().isEmpty() || !status.getRemoved().isEmpty()
                        || !status.getMissing().isEmpty() || !status.getUntracked().isEmpty()) {
                    throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY,
                            "Patch changed files outside the finding's target file.");
                }
                git.add().addFilepattern(filePath).call();
                git.commit()
                        .setMessage("fix(security): remediate finding " + fix.getFinding().getId())
                        .setAuthor("AutoForge Security Bot", "autoforge-bot@users.noreply.github.com")
                        .call();

                Iterable<PushResult> pushResults = git.push()
                        .setRemote("origin")
                        .add(branchName)
                        .setCredentialsProvider(credentials)
                        .call();
                for (PushResult pushResult : pushResults) {
                    for (RemoteRefUpdate update : pushResult.getRemoteUpdates()) {
                        if (update.getStatus() != RemoteRefUpdate.Status.OK
                                && update.getStatus() != RemoteRefUpdate.Status.UP_TO_DATE) {
                            throw new ApiException(HttpStatus.BAD_GATEWAY,
                                    "GitHub rejected the security branch push: " + update.getStatus());
                        }
                    }
                }
            } catch (GitAPIException ex) {
                throw new ApiException(HttpStatus.BAD_GATEWAY,
                        "Could not clone, patch, commit, or push the approved fix to GitHub: " + ex.getMessage());
            }

            try {
                GitHubPullRequestClient.PullRequestDetails pr = pullRequestClient.createPullRequest(
                        repositorySlug, baseBranch, branchName,
                        "AutoForge security fix: " + fix.getFinding().getTitle(),
                        "Automated patch for finding " + fix.getFinding().getId()
                                + ". Review and run the project's tests before merging.");
                return new PublishedPullRequest(repositorySlug, branchName, pr.number(), pr.url(), pr.state());
            } catch (ApiException ex) {
                throw new ApiException(ex.getStatus(),
                        "Branch " + branchName + " was pushed, but pull request creation failed: " + ex.getMessage());
            }
        } finally {
            deleteWorkspace(workspace);
        }
    }

    private String repositorySlug(Scan scan) {
        String candidate = null;
        if (scan.getProject() != null) {
            candidate = scan.getProject().getRepoUrl();
        } else if (scan.getRepository() != null) {
            candidate = scan.getRepository().getGithubRepoFullName();
        }
        if (candidate == null) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "The scan is not linked to a GitHub repository.");
        }
        if (candidate.startsWith("https://github.com/")) {
            candidate = candidate.substring("https://github.com/".length());
        }
        if (candidate.endsWith(".git")) candidate = candidate.substring(0, candidate.length() - 4);
        if (!candidate.matches("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "The scan does not contain a valid GitHub repository URL.");
        }
        return candidate;
    }

    private String branchName(String branch) {
        String candidate = branch == null || branch.isBlank() ? "main" : branch;
        if (!Repository.isValidRefName("refs/heads/" + candidate) || candidate.startsWith("-")) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "The scan's base branch is invalid.");
        }
        return candidate;
    }

    private String validatePatch(Fix fix) {
        String filePath = fix.getFilePath();
        if (filePath == null || filePath.isBlank() || filePath.contains("\\")
                || filePath.contains("\n") || filePath.contains("\r")) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "The patch target file path is invalid.");
        }
        Path path = Path.of(filePath).normalize();
        if (path.isAbsolute() || path.startsWith("..") || !path.toString().replace('\\', '/').equals(filePath)) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "The patch target must be a repository-relative path.");
        }
        String[] lines = fix.getSuggestedPatch().split("\\R");
        if (lines.length < 3 || !lines[0].equals("--- a/" + filePath)
                || !lines[1].equals("+++ b/" + filePath) || !lines[2].startsWith("@@")
                || List.of(lines).stream().skip(3)
                .anyMatch(line -> line.startsWith("--- a/") || line.startsWith("+++ b/")
                        || line.startsWith("diff --git "))) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "The stored patch must be a single-file unified diff for the finding's file.");
        }
        return filePath;
    }

    private void deleteWorkspace(Path workspace) {
        try (var paths = Files.walk(workspace)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        } catch (IOException ex) {
            log.warn("Unable to clean temporary Git workspace {}: {}", workspace, ex.getMessage(), ex);
        }
    }

    public record PublishedPullRequest(String repository, String branch, int number, String url, String state) {
    }
}
