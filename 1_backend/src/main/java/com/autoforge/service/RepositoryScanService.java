package com.autoforge.service;

import com.autoforge.dto.ScanJobResponse;
import com.autoforge.entity.Repository;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.RepositoryRepository;
import com.autoforge.repository.ScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RepositoryScanService {
    private final RepositoryRepository repositoryRepository;
    private final ScanRepository scanRepository;
    private final QueueService queueService;
    private final GitHubRepositoryClient gitHubRepositoryClient;

    @Transactional
    public ScanJobResponse triggerLatestScan(Long repositoryId, String userEmail) {
        Repository repository = ownedRepository(repositoryId, userEmail);
        GitHubRepositoryClient.LatestCommit latest =
                gitHubRepositoryClient.latestCommit(repository.getGithubRepoFullName());

        Scan scan = new Scan();
        scan.setRepository(repository);
        scan.setCommitSha(latest.sha());
        scan.setBranch(latest.branch());
        scan.setStatus(ScanStatus.QUEUED);
        Scan saved = scanRepository.save(scan);

        String repositoryUrl = "https://github.com/" + repository.getGithubRepoFullName() + ".git";
        queueService.publishScanJob(saved.getId(), repository.getId(), repositoryUrl, latest.sha(), latest.branch());
        return toResponse(saved);
    }

    @Transactional(readOnly = true)
    public List<ScanJobResponse> listScans(Long repositoryId, String userEmail) {
        ownedRepository(repositoryId, userEmail);
        return scanRepository.findByRepositoryIdOrderByCreatedAtDesc(repositoryId)
                .stream()
                .map(RepositoryScanService::toResponse)
                .toList();
    }

    private Repository ownedRepository(Long repositoryId, String userEmail) {
        Repository repository = repositoryRepository.findById(repositoryId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Repository not found."));
        if (repository.getUser() == null || repository.getUser().getEmail() == null
                || !repository.getUser().getEmail().equalsIgnoreCase(userEmail)) {
            throw new ApiException(HttpStatus.FORBIDDEN, "You do not own this repository.");
        }
        return repository;
    }

    private static ScanJobResponse toResponse(Scan scan) {
        return ScanJobResponse.builder()
                .id(scan.getId())
                .projectId(scan.getRepository() == null ? null : scan.getRepository().getId())
                .commitSha(scan.getCommitSha())
                .branch(scan.getBranch())
                .changedFiles(scan.getChangedFilePaths() == null || scan.getChangedFilePaths().isBlank()
                        ? List.of() : List.of(scan.getChangedFilePaths().split("\\n")))
                .status(scan.getStatus().name())
                .errorMessage(scan.getErrorMessage())
                .progress(scan.getProgress())
                .progressStage(scan.getProgressStage())
                .progressMessage(scan.getProgressMessage())
                .createdAt(scan.getCreatedAt())
                .completedAt(scan.getCompletedAt())
                .build();
    }
}
