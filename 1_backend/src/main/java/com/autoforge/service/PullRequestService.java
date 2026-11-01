package com.autoforge.service;

import com.autoforge.dto.PullRequestResponseDto;
import com.autoforge.entity.Fix;
import com.autoforge.entity.PullRequest;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.FixRepository;
import com.autoforge.repository.PullRequestRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PullRequestService {
    private final FixRepository fixRepository;
    private final PullRequestRepository pullRequestRepository;
    private final AuditLogService auditLogService;
    private final GitHubPatchPublisher patchPublisher;

    public PullRequestResponseDto createPullRequest(Long fixId, String userEmail) {
        Fix fix = fixRepository.findById(fixId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Fix not found: " + fixId));

        if (fix.getFinding() == null || fix.getFinding().getScan() == null || !isOwnedBy(fix, userEmail)) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Fix not found: " + fixId);
        }
        List<PullRequest> existing = pullRequestRepository.findByFixId(fixId);
        if (!existing.isEmpty()) {
            PullRequest pr = existing.get(0);
            return toDto(pr);
        }
        if (!"APPROVED".equals(fix.getStatus())) {
            throw new ApiException(HttpStatus.CONFLICT, "Only an approved fix can be pushed to GitHub.");
        }

        GitHubPatchPublisher.PublishedPullRequest published = patchPublisher.publish(fix);

        PullRequest pr = new PullRequest();
        pr.setFix(fix);
        pr.setBranchName(published.branch());
        pr.setGithubPrNumber(published.number());
        pr.setGithubPrUrl(published.url());
        pr.setStatus(published.state());

        PullRequest saved = pullRequestRepository.save(pr);
        fix.setStatus("PR_CREATED");
        fixRepository.save(fix);

        auditLogService.log("PR_CREATED", "GitHub Pull Request #" + saved.getGithubPrNumber()
                + " created for fix ID " + fixId + " (" + saved.getGithubPrUrl() + ")");
        log.info("Created pull request {} for fix {}", saved.getId(), fixId);
        return toDto(saved);
    }

    private boolean isOwnedBy(Fix fix, String userEmail) {
        var scan = fix.getFinding().getScan();
        if (scan.getProject() != null && scan.getProject().getUser() != null) {
            return userEmail.equalsIgnoreCase(scan.getProject().getUser().getEmail());
        }
        return scan.getRepository() != null && scan.getRepository().getUser() != null
                && userEmail.equalsIgnoreCase(scan.getRepository().getUser().getEmail());
    }

    private PullRequestResponseDto toDto(PullRequest pr) {
        return PullRequestResponseDto.builder()
                .id(pr.getId())
                .fixId(pr.getFix().getId())
                .githubPrNumber(pr.getGithubPrNumber())
                .githubPrUrl(pr.getGithubPrUrl())
                .branchName(pr.getBranchName())
                .status(pr.getStatus())
                .createdAt(pr.getCreatedAt())
                .build();
    }
}
