package com.autoforge.service;

import com.autoforge.dto.ScanJobResponse;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.entity.User;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.ScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.io.IOException;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class ScanExecutionService {
    private final ScanRepository scanRepository;
    private final ScanSourceStorageService storageService;
    private final ScanProcessWorker scanProcessWorker;
    private final ScanService scanService;

    @Transactional
    public ScanJobResponse startScan(Long scanId, String userEmail) throws IOException {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));
        User owner = scan.getProject() != null ? scan.getProject().getUser() : null;
        if (owner == null || !userEmail.equals(owner.getEmail())) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId);
        }
        if (scan.getStatus() != ScanStatus.QUEUED) {
            throw new ApiException(HttpStatus.CONFLICT, "Only queued scans can be started.");
        }
        if (scan.getSourcePath() == null || scan.getSourcePath().isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Scan has no local source directory. Upload or import a source directory first.");
        }

        var sourceDirectory = storageService.validateSourceDirectory(scan.getSourcePath());
        Instant startedAt = Instant.now();
        int claimed = scanRepository.claimQueuedScan(scanId, startedAt);
        if (claimed == 0) {
            throw new ApiException(HttpStatus.CONFLICT, "Scan is already running or no longer queued.");
        }
        scan.setStatus(ScanStatus.RUNNING);
        scan.setStartedAt(startedAt);
        scan.setProgress(1);
        scanRepository.save(scan);
        dispatchAfterCommit(() -> scanProcessWorker.execute(scan.getId(), sourceDirectory.toString()));
        return scanService.getScanJob(scan.getId());
    }

    @Transactional
    public void startQueuedRepositoryScan(Long scanId, String repositoryUrl, String commitSha, String branch) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));
        if (scan.getStatus() != ScanStatus.QUEUED) {
            throw new ApiException(HttpStatus.CONFLICT, "Only queued scans can be started.");
        }
        Instant startedAt = Instant.now();
        int claimed = scanRepository.claimQueuedScan(scanId, startedAt);
        if (claimed == 0) {
            throw new ApiException(HttpStatus.CONFLICT, "Scan is already running or no longer queued.");
        }
        scan.setStatus(ScanStatus.RUNNING);
        scan.setStartedAt(startedAt);
        scan.setProgress(1);
        scanRepository.save(scan);
        dispatchAfterCommit(() -> scanProcessWorker.executeRemote(scanId, repositoryUrl, commitSha, branch));
    }

    @Transactional
    public boolean recoverInterruptedScan(Long scanId, Instant staleBefore) {
        int recovered = scanRepository.requeueStaleScan(scanId, staleBefore,
                "Previous scan worker stopped unexpectedly; scan was restarted.");
        if (recovered == 0) {
            return false;
        }

        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));
        Instant startedAt = Instant.now();
        if (scanRepository.claimQueuedScan(scanId, startedAt) == 0) {
            return false;
        }
        scan.setStatus(ScanStatus.RUNNING);
        scan.setStartedAt(startedAt);
        scan.setProgress(1);
        scanRepository.save(scan);

        if (scan.getSourcePath() != null && !scan.getSourcePath().isBlank()) {
            String sourcePath = scan.getSourcePath();
            dispatchAfterCommit(() -> scanProcessWorker.execute(scanId, sourcePath));
        } else {
            String repositoryUrl = scan.getRepository() != null
                    ? scan.getRepository().getGithubRepoFullName()
                    : scan.getProject() != null ? scan.getProject().getRepoUrl() : null;
            if (repositoryUrl == null || repositoryUrl.isBlank()) {
                scan.setStatus(ScanStatus.FAILED);
                scan.setCompletedAt(Instant.now());
                scan.setErrorMessage("Cannot recover scan: no source directory or repository URL is linked.");
                scanRepository.save(scan);
                return true;
            }
            if (!repositoryUrl.startsWith("https://")) {
                repositoryUrl = "https://github.com/" + repositoryUrl;
            }
            String remoteUrl = repositoryUrl;
            String commitSha = scan.getCommitSha();
            String branch = scan.getBranch();
            dispatchAfterCommit(() -> scanProcessWorker.executeRemote(scanId, remoteUrl, commitSha, branch));
        }
        return true;
    }

    private void dispatchAfterCommit(Runnable dispatch) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            dispatch.run();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                dispatch.run();
            }
        });
    }
}
