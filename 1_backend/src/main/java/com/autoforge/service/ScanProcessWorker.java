package com.autoforge.service;

import com.autoforge.exception.ApiException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.net.URI;
import java.util.Base64;

@Component
@RequiredArgsConstructor
@Slf4j
public class ScanProcessWorker {
    private static final int MAX_SCAN_ERROR_LENGTH = 1000;

    private final ScanService scanService;
    private final ScanSourceStorageService storageService;
    private final ScannerProcessExecutor processExecutor;
    private final ObjectMapper objectMapper;

    @Value("${autoforge.scanner.python-executable:python}")
    private String pythonExecutable;

    @Value("${autoforge.scanner.wrapper-path:../2_pipeline/scanners/scan_wrapper.py}")
    private String wrapperPath;

    @Value("${autoforge.scanner.timeout:PT15M}")
    private Duration timeout;

    @Value("${autoforge.scanner.git-executable:git}")
    private String gitExecutable;

    @Value("${autoforge.github.token:}")
    private String githubToken;

    @Async("scanTaskExecutor")
    public void execute(Long scanId, String sourcePath) {
        try {
            Path sourceDirectory = storageService.validateSourceDirectory(sourcePath);
            runScanner(scanId, sourceDirectory);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            failScan(scanId, "Scanner process was interrupted.");
        } catch (Exception ex) {
            log.error("Scanner process failed for scan {}: {}", scanId, ex.getMessage(), ex);
            failScan(scanId, errorMessage(ex));
        }
    }

    @Async("scanTaskExecutor")
    public void executeRemote(Long scanId, String repositoryUrl, String commitSha, String branch) {
        Path workspace = null;
        try {
            workspace = storageService.createRemoteWorkspace();
            Path sourceDirectory = workspace.resolve("repository");
            cloneRepository(repositoryUrl, commitSha, branch, sourceDirectory, workspace);
            runScanner(scanId, sourceDirectory);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            failScan(scanId, "Remote scan process was interrupted.");
        } catch (Exception ex) {
            log.error("Remote scan failed for scan {}: {}", scanId, ex.getMessage(), ex);
            failScan(scanId, errorMessage(ex));
        } finally {
            if (workspace != null) {
                try {
                    storageService.deleteRemoteWorkspace(workspace);
                } catch (java.io.IOException cleanupFailure) {
                    log.error("Unable to clean remote scan workspace for scan {}: {}", scanId,
                            cleanupFailure.getMessage(), cleanupFailure);
                }
            }
        }
    }

    private void runScanner(Long scanId, Path sourceDirectory) throws Exception {
        Path script = Path.of(wrapperPath).toAbsolutePath().normalize();
        if (!Files.isRegularFile(script)) {
            throw new IllegalStateException("Scanner wrapper was not found: " + script);
        }
        Path resultFile = storageService.resultFileFor(scanId);
        List<String> command = List.of(
                pythonExecutable,
                script.toString(),
                "--source-dir", sourceDirectory.toString(),
                "--output", resultFile.toString()
        );
        ScannerProcessExecutor.ProcessResult result = processExecutor.execute(command, sourceDirectory, timeout);
        if (!result.finished()) {
            throw new IllegalStateException("Scanner process exceeded timeout " + timeout + ".");
        }
        if (result.exitCode() != 0) {
            throw new IllegalStateException("Scanner process exited with code " + result.exitCode() + ": " + result.output());
        }
        if (!Files.isRegularFile(resultFile)) {
            throw new IllegalStateException("Scanner exited successfully but did not create " + resultFile.getFileName() + ".");
        }
        JsonNode results = objectMapper.readTree(resultFile.toFile());
        scanService.persistScoredResults(scanId, results);
        log.info("Scanner process completed for scan {}.", scanId);
    }

    private void cloneRepository(String repositoryUrl, String commitSha, String branch, Path destination, Path workingDirectory)
            throws Exception {
        URI uri = URI.create(repositoryUrl);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || !"github.com".equalsIgnoreCase(uri.getHost())
                || uri.getRawUserInfo() != null || uri.getPort() != -1 || uri.getRawQuery() != null || uri.getRawFragment() != null
                || uri.getPath() == null || !uri.getPath().matches("/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\\.git)?")) {
            throw new IllegalArgumentException("Only HTTPS repositories hosted on github.com can be scanned.");
        }
        List<String> command;
        if (commitSha != null && !commitSha.isBlank()) {
            if (!commitSha.matches("[a-fA-F0-9]{7,64}")) {
                throw new IllegalArgumentException("Repository commit SHA is invalid.");
            }
            command = List.of(gitExecutable, "clone", "--filter=blob:none", "--no-checkout", "--", repositoryUrl, destination.toString());
        } else {
            String selectedBranch = branch == null || branch.isBlank() ? "main" : branch;
            if (!selectedBranch.matches("[A-Za-z0-9_./-]{1,128}") || selectedBranch.startsWith("-")
                    || selectedBranch.contains("..") || selectedBranch.endsWith("/")) {
                throw new IllegalArgumentException("Repository branch is invalid.");
            }
            command = List.of(gitExecutable, "clone", "--depth", "1", "--branch", selectedBranch,
                    "--", repositoryUrl, destination.toString());
        }
        Map<String, String> environment = new java.util.HashMap<>();
        environment.put("GIT_TERMINAL_PROMPT", "0");
        if (!githubToken.isBlank()) {
            String auth = Base64.getEncoder().encodeToString(("x-access-token:" + githubToken).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            environment.put("GIT_CONFIG_COUNT", "1");
            environment.put("GIT_CONFIG_KEY_0", "http.https://github.com/.extraheader");
            environment.put("GIT_CONFIG_VALUE_0", "AUTHORIZATION: basic " + auth);
        }
        ScannerProcessExecutor.ProcessResult clone = processExecutor.execute(command, workingDirectory, timeout, environment);
        if (!clone.finished() || clone.exitCode() != 0) {
            throw new IllegalStateException(clone.finished()
                    ? "Git clone failed with exit code " + clone.exitCode() + ": " + clone.output()
                    : "Git clone exceeded timeout " + timeout + ".");
        }
        if (commitSha != null && !commitSha.isBlank()) {
            ScannerProcessExecutor.ProcessResult fetch = processExecutor.execute(
                    List.of(gitExecutable, "-C", destination.toString(), "fetch", "--depth", "1", "origin", commitSha),
                    workingDirectory, timeout, environment);
            if (!fetch.finished() || fetch.exitCode() != 0) {
                throw new IllegalStateException(fetch.finished()
                        ? "Git fetch failed with exit code " + fetch.exitCode() + ": " + fetch.output()
                        : "Git fetch exceeded timeout " + timeout + ".");
            }
            ScannerProcessExecutor.ProcessResult checkout = processExecutor.execute(
                    List.of(gitExecutable, "-C", destination.toString(), "checkout", "--detach", "FETCH_HEAD"),
                    workingDirectory, timeout, environment);
            if (!checkout.finished() || checkout.exitCode() != 0) {
                throw new IllegalStateException(checkout.finished()
                        ? "Git checkout failed with exit code " + checkout.exitCode() + ": " + checkout.output()
                        : "Git checkout exceeded timeout " + timeout + ".");
            }
        }
    }

    private String errorMessage(Exception exception) {
        String message = exception.getMessage() != null ? exception.getMessage() : "Scanner process failed.";
        if (message.length() <= MAX_SCAN_ERROR_LENGTH) {
            return message;
        }
        return message.substring(0, MAX_SCAN_ERROR_LENGTH - 15) + " [truncated]";
    }

    private void failScan(Long scanId, String message) {
        try {
            scanService.updateScanStatus(scanId, "FAILED", message);
        } catch (ApiException ex) {
            log.error("Unable to record scanner failure for scan {}: {}", scanId, ex.getMessage(), ex);
        }
    }
}
