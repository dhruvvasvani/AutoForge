package com.autoforge.service;

import com.autoforge.entity.Scan;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.ScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class GitHubQualityGatePublisher {
    private final ScanRepository scanRepository;
    private final GitHubCommitStatusClient commitStatusClient;

    @Transactional(readOnly = true)
    public void publish(Long scanId, String userEmail, boolean passed, String description) {
        Scan scan = scanRepository.findVisibleScanById(scanId, userEmail)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));
        String repository = repositorySlug(scan);
        commitStatusClient.publish(repository, scan.getCommitSha(), passed, description);
    }

    private String repositorySlug(Scan scan) {
        String value = scan.getRepository() != null
                ? scan.getRepository().getGithubRepoFullName()
                : scan.getProject() != null ? scan.getProject().getRepoUrl() : null;
        if (value == null) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "The scan is not linked to a GitHub repository.");
        }
        if (value.startsWith("https://github.com/")) {
            value = value.substring("https://github.com/".length());
        }
        if (value.endsWith(".git")) {
            value = value.substring(0, value.length() - 4);
        }
        if (!value.matches("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "The scan is not linked to a valid GitHub repository.");
        }
        return value;
    }
}
