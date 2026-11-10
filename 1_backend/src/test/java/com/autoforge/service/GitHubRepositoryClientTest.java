package com.autoforge.service;

import com.autoforge.exception.ApiException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GitHubRepositoryClientTest {
    @Test
    void parsesDefaultBranchAndCommitFromGitHead() {
        String sha = "6a43e098d78b3f56d32be929cad0709ab99af4b6";

        GitHubRepositoryClient.LatestCommit commit = GitHubRepositoryClient.parseGitHead(
                "ref: refs/heads/main\tHEAD\n" + sha + "\tHEAD\n");

        assertEquals("main", commit.branch());
        assertEquals(sha, commit.sha());
    }

    @Test
    void rejectsGitHeadWithoutDefaultBranch() {
        ApiException error = assertThrows(ApiException.class,
                () -> GitHubRepositoryClient.parseGitHead("not a git ref\n"));

        assertEquals(404, error.getStatus().value());
    }
}
