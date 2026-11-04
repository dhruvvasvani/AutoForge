package com.autoforge.service;

import com.autoforge.dto.*;
import com.autoforge.entity.*;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
@Transactional
public class ScanService {
    private final RepositoryRepository repositoryRepository;
    private final ProjectRepository projectRepository;
    private final WebhookEventRepository webhookEventRepository;
    private final ScanRepository scanRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final FindingRepository findingRepository;
    private final CallTraceRepository callTraceRepository;
    private final MLPredictionRepository mlPredictionRepository;
    private final QueueService queueService;
    private final AstMetricsRepository astMetricsRepository;
    private final RemediationService remediationService;

    public Scan createScanJobFromPush(String repoFullName, String commitSha, String eventType) {
        return createScanJobFromPush(repoFullName, commitSha, eventType, "main", List.of());
    }

    public Scan createScanJobFromPush(String repoFullName, String commitSha, String eventType,
                                      String branch, List<String> changedFiles) {
        return createOrGetScanJobFromPush(repoFullName, commitSha, eventType, branch, changedFiles).scan();
    }

    public ScanCreationResult createOrGetScanJobFromPush(String repoFullName, String commitSha, String eventType,
                                                          String branch, List<String> changedFiles) {
        Repository repository = repositoryRepository.findByGithubRepoFullName(repoFullName)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Repository is not connected to AutoForge: " + repoFullName));

        var existingScan = scanRepository.findFirstByRepositoryIdAndCommitSha(repository.getId(), commitSha);
        if (existingScan.isPresent()) {
            return new ScanCreationResult(existingScan.get(), false);
        }

        WebhookEvent event = new WebhookEvent();
        event.setRepository(repository);
        event.setEventType(eventType);
        event.setCommitSha(commitSha);
        webhookEventRepository.save(event);

        Scan scan = new Scan();
        scan.setRepository(repository);
        scan.setWebhookEvent(event);
        scan.setCommitSha(commitSha);
        scan.setBranch(branch == null || branch.isBlank() ? "main" : branch);
        scan.setChangedFilePaths(changedFiles == null || changedFiles.isEmpty()
                ? null : String.join("\n", changedFiles));
        scan.setStatus(ScanStatus.QUEUED);
        Scan saved = scanRepository.save(scan);

        String repoUrl = repository.getGithubRepoFullName().startsWith("http")
                ? repository.getGithubRepoFullName()
                : "https://github.com/" + repository.getGithubRepoFullName();

        queueService.publishScanJob(saved.getId(), repository.getId(), repoUrl, commitSha,
                saved.getBranch(), changedFiles);
        return new ScanCreationResult(saved, true);
    }

    public record ScanCreationResult(Scan scan, boolean created) {}

    public ScanJobResponse triggerScan(ScanTriggerRequest request) {
        if (request.getIdempotencyKey() != null && !request.getIdempotencyKey().isBlank()) {
            var existing = scanRepository.findByIdempotencyKey(request.getIdempotencyKey());
            if (existing.isPresent()) {
                log.info("Duplicate scan request detected with idempotency key: {}", request.getIdempotencyKey());
                return toJobResponse(existing.get());
            }
        }

        Project project = projectRepository.findById(request.getProjectId())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Project not found: " + request.getProjectId()));

        Scan scan = new Scan();
        scan.setProject(project);
        scan.setCommitSha(request.getCommitSha());
        scan.setBranch(request.getBranch() != null ? request.getBranch() : project.getDefaultBranch());
        scan.setStatus(ScanStatus.QUEUED);
        scan.setIdempotencyKey(request.getIdempotencyKey());

        Scan saved = scanRepository.save(scan);
        queueService.publishScanJob(saved.getId(), project.getId(), project.getRepoUrl(), saved.getCommitSha(), saved.getBranch());
        return toJobResponse(saved);
    }

    public ScanJobResponse getScanJob(Long jobId) {
        Scan scan = scanRepository.findById(jobId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + jobId));
        return toJobResponse(scan);
    }

    public List<ScanJobResponse> listScansForProject(Long projectId, int skip, int limit) {
        int pageNumber = skip / (limit > 0 ? limit : 10);
        int pageSize = limit > 0 ? limit : 10;
        PageRequest pageRequest = PageRequest.of(pageNumber, pageSize, Sort.by(Sort.Direction.DESC, "createdAt"));
        return scanRepository.findByProjectId(projectId, pageRequest)
                .stream()
                .map(this::toJobResponse)
                .toList();
    }

    public List<ScanJobResponse> listScans(int skip, int limit, String userEmail) {
        int pageSize = Math.max(1, Math.min(limit, 100));
        int pageNumber = Math.max(0, skip) / pageSize;
        PageRequest pageRequest = PageRequest.of(pageNumber, pageSize, Sort.by(Sort.Direction.DESC, "createdAt"));
        return scanRepository.findVisibleToUser(userEmail, pageRequest)
                .stream()
                .map(this::toJobResponse)
                .toList();
    }

    public ScanJobResponse updateScanStatus(Long scanId, String statusStr, String errorMessage) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));

        ScanStatus newStatus = ScanStatus.valueOf(statusStr.toUpperCase());
        scan.setStatus(newStatus);
        if (errorMessage != null) {
            scan.setErrorMessage(errorMessage);
        }
        if ((newStatus == ScanStatus.PROCESSING || newStatus == ScanStatus.RUNNING) && scan.getStartedAt() == null) {
            scan.setStartedAt(Instant.now());
        }
        if (newStatus == ScanStatus.COMPLETED || newStatus == ScanStatus.FAILED) {
            scan.setCompletedAt(Instant.now());
        }
        if (newStatus == ScanStatus.COMPLETED) {
            scan.setProgress(100);
        }
        return toJobResponse(scanRepository.save(scan));
    }

    public void failQueuedScan(Long scanId, String errorMessage) {
        String message = errorMessage == null ? "Unable to start queued scan."
                : errorMessage.substring(0, Math.min(errorMessage.length(), 1000));
        scanRepository.failQueuedScan(scanId, message, Instant.now());
    }

    public Scan persistScanResults(Long scanId, ScanResultsPayload payload) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));

        if ("FAILED".equalsIgnoreCase(payload.getStatus())) {
            scan.setStatus(ScanStatus.FAILED);
            scan.setErrorMessage(payload.getError() == null ? "Pipeline worker reported scan failure."
                    : payload.getError().substring(0, Math.min(payload.getError().length(), 1024)));
            scan.setCompletedAt(Instant.now());
            return scanRepository.save(scan);
        }

        String defaultPriority = payload.getPriority() != null ? payload.getPriority() : payload.getMlPriority();
        Boolean defaultReachable = payload.getIsReachable();
        if (defaultReachable == null && payload.getReachabilityTag() != null) {
            defaultReachable = !"UNREACHABLE".equalsIgnoreCase(payload.getReachabilityTag());
        }

        if (payload.getSemgrep() != null) {
            final Boolean reach = defaultReachable;
            final String prio = defaultPriority;
            payload.getSemgrep().forEach(f -> {
                vulnerabilityRepository.save(toVulnerability(scan, f, "SEMGREP", reach, prio));
                Finding savedFinding = findingRepository.save(toFinding(scan, f));
                try {
                    remediationService.generateAutomatically(savedFinding);
                } catch (Exception ex) {
                    log.warn("Automatic remediation failed for finding {}: {}",
                            savedFinding.getId(), ex.getMessage());
                }
            });
        }
        if (payload.getCheckov() != null) {
            final Boolean reach = defaultReachable;
            final String prio = defaultPriority;
            payload.getCheckov().forEach(f -> {
                vulnerabilityRepository.save(toVulnerability(scan, f, "CHECKOV", reach, prio));
                Finding savedFinding = findingRepository.save(toFinding(scan, f));
                try {
                    remediationService.generateAutomatically(savedFinding);
                } catch (Exception ex) {
                    log.warn("Automatic remediation failed for finding {}: {}",
                            savedFinding.getId(), ex.getMessage());
                }
            });
        }

        scan.setStatus(ScanStatus.COMPLETED);
        scan.setCompletedAt(Instant.now());
        scan.setProgress(100);
        return scanRepository.save(scan);
    }

    public Scan persistScanResults(Long scanId, JsonNode semgrepFindings, JsonNode checkovFindings) {
        ScanResultsPayload payload = new ScanResultsPayload();
        payload.setSemgrep(semgrepFindings);
        payload.setCheckov(checkovFindings);
        return persistScanResults(scanId, payload);
    }

    public void persistHybridScanResults(HybridScanPayload payload) {
        Scan scan = scanRepository.findById(payload.getJobId())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan job not found: " + payload.getJobId()));

        if (payload.getFindings() != null) {
            for (HybridFindingDto dto : payload.getFindings()) {
                Finding finding = new Finding();
                finding.setScan(scan);
                finding.setRuleId(dto.getRuleId() != null ? dto.getRuleId() : "GENERIC-001");
                finding.setTitle(dto.getTitle() != null ? dto.getTitle() : "Security Finding");
                finding.setFilePath(dto.getFilePath() != null ? dto.getFilePath() : "unknown");
                finding.setLineNumber(dto.getLineNumber() != null ? dto.getLineNumber() : 0);
                finding.setSeverity(dto.getSeverity() != null ? dto.getSeverity().toUpperCase() : "MEDIUM");
                finding.setCodeSnippet(dto.getCodeSnippet());
                Finding savedFinding = findingRepository.save(finding);

                if (dto.getCallTraces() != null) {
                    for (CallTraceStepDto traceDto : dto.getCallTraces()) {
                        CallTrace trace = new CallTrace();
                        trace.setFinding(savedFinding);
                        trace.setStepNumber(traceDto.getStepNumber() != null ? traceDto.getStepNumber() : 1);
                        trace.setFilePath(traceDto.getFilePath() != null ? traceDto.getFilePath() : savedFinding.getFilePath());
                        trace.setLineNumber(traceDto.getLineNumber() != null ? traceDto.getLineNumber() : savedFinding.getLineNumber());
                        trace.setSymbolName(traceDto.getSymbolName() != null ? traceDto.getSymbolName() : "function");
                        callTraceRepository.save(trace);
                    }
                }

                if (dto.getMlConfidenceScore() != null) {
                    MLPrediction ml = new MLPrediction();
                    ml.setFinding(savedFinding);
                    ml.setMlConfidenceScore(dto.getMlConfidenceScore());
                    ml.setModelVersion("v1.0.0");
                    mlPredictionRepository.save(ml);
                }
            }
        }

        scan.setStatus(ScanStatus.COMPLETED);
        scan.setCompletedAt(Instant.now());
        scanRepository.save(scan);
    }

    public void persistScoredResults(Long scanId, JsonNode results) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan job not found: " + scanId));
        if (results == null || !results.isObject()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Scanner result must be a JSON object.");
        }

        JsonNode resultJobId = results.has("job_id") ? results.get("job_id") : results.get("scan_id");
        if (resultJobId != null && !resultJobId.isNull() && !resultJobId.asText().equals(scanId.toString())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Scanner result job_id does not match the scan.");
        }
        if (!results.has("findings") && !results.has("scored_findings")
                && !results.has("semgrep") && !results.has("checkov")) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Scanner result must include a findings array.");
        }

        List<JsonNode> rawFindings = new java.util.ArrayList<>();
        JsonNode findingsNode = results.has("findings") ? results.get("findings") : results.get("scored_findings");
        appendFindingArray(rawFindings, findingsNode, null);
        appendFindingArray(rawFindings, results.get("semgrep"), "SEMGREP");
        appendFindingArray(rawFindings, results.get("checkov"), "CHECKOV");

        ObjectMapper mapper = new ObjectMapper();
        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;
        for (JsonNode raw : rawFindings) {
            ScoredFindingDto dto = mapper.convertValue(raw, ScoredFindingDto.class);
            if (dto.getRuleId() == null || dto.getRuleId().isBlank()) {
                dto.setRuleId(raw.path("check_id").asText(null));
            }
            if (dto.getTitle() == null || dto.getTitle().isBlank()) {
                dto.setTitle(raw.path("description").asText(raw.path("message").asText(
                        raw.path("extra").path("message").asText(raw.path("check_name").asText(null)))));
            }
            if (dto.getFilePath() == null || dto.getFilePath().isBlank()) {
                dto.setFilePath(raw.path("path").asText(raw.path("file_abs_path").asText(null)));
            }
            if (dto.getLineNumber() == null) {
                int line = raw.path("start").path("line").asInt(
                        raw.path("location").path("start").path("line").asInt(0));
                dto.setLineNumber(line);
            }
            if (dto.getSeverity() == null || dto.getSeverity().isBlank()) {
                dto.setSeverity(raw.path("extra").path("severity").asText(
                        raw.path("severity").asText("MEDIUM")));
            }
            if (dto.getCodeSnippet() == null) {
                dto.setCodeSnippet(raw.path("extra").path("lines").asText(
                        raw.path("code").asText(null)));
            }
            if (dto.getReachable() == null && raw.path("extra").has("is_reachable")) {
                dto.setReachable(raw.path("extra").path("is_reachable").asBoolean());
            }
            if (dto.getReachabilityStatus() == null && raw.path("extra").has("reachability")) {
                dto.setReachabilityStatus(raw.path("extra").path("reachability").asText());
            }
            if (dto.getReachable() == null && dto.getReachabilityStatus() != null) {
                dto.setReachable(isReachableStatus(dto.getReachabilityStatus()));
            }

            if (dto.getRuleId() == null || dto.getRuleId().isBlank()
                    || dto.getTitle() == null || dto.getTitle().isBlank()
                    || dto.getFilePath() == null || dto.getFilePath().isBlank()
                    || dto.getLineNumber() == null || dto.getLineNumber() < 0) {
                throw new ApiException(HttpStatus.BAD_REQUEST,
                        "Each scanner finding must include rule_id, title, file_path, and a non-negative line_number.");
            }

            String severity = dto.getSeverity().trim().toUpperCase();
            if (!List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").contains(severity)) {
                throw new ApiException(HttpStatus.BAD_REQUEST, "Unsupported finding severity: " + dto.getSeverity());
            }
            Finding finding = new Finding();
            finding.setScan(scan);
            finding.setRuleId(dto.getRuleId());
            finding.setTitle(dto.getTitle());
            finding.setFilePath(dto.getFilePath());
            finding.setLineNumber(dto.getLineNumber());
            finding.setSeverity(severity);
            finding.setCodeSnippet(dto.getCodeSnippet());
            finding.setIsReachable(dto.getReachable());
            finding.setReachabilityStatus(dto.getReachabilityStatus());
            finding.setPriority(dto.getPriority());
            Finding savedFinding = findingRepository.save(finding);

            if (dto.getCallTraces() != null) {
                for (CallTraceStepDto traceDto : dto.getCallTraces()) {
                    if (traceDto.getFilePath() == null || traceDto.getLineNumber() == null) {
                        throw new ApiException(HttpStatus.BAD_REQUEST,
                                "Call trace entries must include file_path and line_number.");
                    }
                    CallTrace trace = new CallTrace();
                    trace.setFinding(savedFinding);
                    trace.setStepNumber(traceDto.getStepNumber() != null ? traceDto.getStepNumber() : 1);
                    trace.setFilePath(traceDto.getFilePath());
                    trace.setLineNumber(traceDto.getLineNumber());
                    trace.setSymbolName(traceDto.getSymbolName() != null ? traceDto.getSymbolName() : "function");
                    callTraceRepository.save(trace);
                }
            }

            if (dto.getMlConfidenceScore() != null) {
                if (dto.getMlConfidenceScore() < 0 || dto.getMlConfidenceScore() > 1) {
                    throw new ApiException(HttpStatus.BAD_REQUEST, "ML confidence score must be between 0 and 1.");
                }
                MLPrediction prediction = new MLPrediction();
                prediction.setFinding(savedFinding);
                prediction.setMlConfidenceScore(dto.getMlConfidenceScore());
                prediction.setFeatureVectorSummary(dto.getPriority());
                mlPredictionRepository.save(prediction);
            }
            switch (severity) {
                case "CRITICAL" -> critical++;
                case "HIGH" -> high++;
                case "MEDIUM" -> medium++;
                case "LOW" -> low++;
                default -> { }
            }
        }

        try {
            JsonNode metrics = results.has("metrics") ? results.get("metrics") : mapper.createObjectNode()
                    .put("finding_count", rawFindings.size())
                    .put("critical_count", critical)
                    .put("high_count", high)
                    .put("medium_count", medium)
                    .put("low_count", low);
            AstMetrics astMetrics = astMetricsRepository.findByScanId(scanId).orElseGet(AstMetrics::new);
            astMetrics.setScan(scan);
            astMetrics.setMetricsJson(mapper.writeValueAsString(metrics));
            astMetricsRepository.save(astMetrics);
            scan.setStatus(ScanStatus.COMPLETED);
            scan.setCompletedAt(Instant.now());
            scan.setProgress(100);
            scanRepository.save(scan);
        } catch (com.fasterxml.jackson.core.JsonProcessingException ex) {
            throw new IllegalStateException("Unable to serialize scanner metrics.", ex);
        }
    }

    private void appendFindingArray(List<JsonNode> findings, JsonNode candidate, String scanner) {
        if (candidate == null || candidate.isNull()) {
            return;
        }
        if (!candidate.isArray()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Scanner findings must be JSON arrays.");
        }
        candidate.forEach(finding -> {
            if (!finding.isObject()) {
                throw new ApiException(HttpStatus.BAD_REQUEST, "Each scanner finding must be a JSON object.");
            }
            if (scanner != null && !finding.has("source_scanner")) {
                ((com.fasterxml.jackson.databind.node.ObjectNode) finding).put("source_scanner", scanner);
            }
            findings.add(finding);
        });
    }

    private boolean isReachableStatus(String status) {
        return !List.of("UNREACHABLE", "UNREACHABLE_NOISE", "FALSE_POSITIVE", "NOT_REACHABLE")
                .contains(status.trim().toUpperCase());
    }

    @Transactional(readOnly = true)
    public ScanDetailResultResponse getScanResults(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));

        List<Finding> findings = findingRepository.findByScanId(scanId);
        int critical = 0, high = 0, medium = 0, low = 0;
        List<FindingResponseDto> findingDtos = new java.util.ArrayList<>();
        for (Finding f : findings) {
            String sev = f.getSeverity() != null ? f.getSeverity().toUpperCase() : "MEDIUM";
            switch (sev) {
                case "CRITICAL" -> critical++;
                case "HIGH" -> high++;
                case "MEDIUM" -> medium++;
                case "LOW" -> low++;
            }
            findingDtos.add(FindingResponseDto.builder()
                    .id(f.getId())
                    .scanId(scan.getId())
                    .ruleId(f.getRuleId())
                    .title(f.getTitle())
                    .filePath(f.getFilePath())
                    .lineNumber(f.getLineNumber())
                    .severity(f.getSeverity())
                    .codeSnippet(f.getCodeSnippet())
                    .build());
        }

        int penalty = (critical * 25) + (high * 10) + (medium * 3) + (low * 1);
        int healthScore = Math.max(0, 100 - penalty);

        List<MLPredictionResponseDto> predictions = getScanMLPredictions(scanId);
        Long projId = scan.getProject() != null ? scan.getProject().getId() : (scan.getRepository() != null ? scan.getRepository().getId() : null);

        return ScanDetailResultResponse.builder()
                .scanId(scan.getId())
                .projectId(projId)
                .commitSha(scan.getCommitSha())
                .branch(scan.getBranch())
                .status(scan.getStatus().name())
                .errorMessage(scan.getErrorMessage())
                .progress(scan.getProgress())
                .createdAt(scan.getCreatedAt())
                .startedAt(scan.getStartedAt())
                .completedAt(scan.getCompletedAt())
                .totalFindings(findings.size())
                .severityCounts(new SeverityCountsDto(critical, high, medium, low))
                .healthScore(healthScore)
                .findings(findingDtos)
                .mlPredictions(predictions)
                .build();
    }

    @Transactional(readOnly = true)
    public List<MLPredictionResponseDto> getScanMLPredictions(Long scanId) {
        return mlPredictionRepository.findByFindingScanId(scanId).stream()
                .map(ml -> MLPredictionResponseDto.builder()
                        .id(ml.getId())
                        .findingId(ml.getFinding().getId())
                        .mlConfidenceScore(ml.getMlConfidenceScore())
                        .modelVersion(ml.getModelVersion())
                        .featureVectorSummary(ml.getFeatureVectorSummary())
                        .createdAt(ml.getCreatedAt())
                        .build())
                .toList();
    }

    private Vulnerability toVulnerability(Scan scan, JsonNode finding, String sourceScanner, Boolean defaultReachable, String defaultPriority) {
        Vulnerability v = new Vulnerability();
        v.setScan(scan);
        v.setSourceScanner(sourceScanner);
        v.setFilePath(finding.path("path").asText(finding.path("file_abs_path").asText(null)));
        v.setLineNumber(finding.path("start").path("line").asInt(0));
        v.setRuleId(finding.path("check_id").asText(finding.path("check_id").asText(null)));
        v.setSeverity(finding.path("extra").path("severity").asText("MEDIUM"));
        v.setDescription(finding.path("extra").path("message").asText(finding.path("check_name").asText("")));

        Boolean reachable = defaultReachable;
        if (finding.has("is_reachable")) {
            reachable = finding.get("is_reachable").asBoolean();
        } else if (finding.path("extra").has("reachable")) {
            reachable = finding.path("extra").get("reachable").asBoolean();
        } else if (finding.path("extra").has("is_reachable")) {
            reachable = finding.path("extra").get("is_reachable").asBoolean();
        } else if (finding.path("extra").has("reachability")) {
            reachable = isReachableStatus(finding.path("extra").get("reachability").asText());
        }
        v.setIsReachable(reachable != null ? reachable : true);

        String priority = defaultPriority;
        if (finding.has("priority")) {
            priority = finding.get("priority").asText();
        } else if (finding.path("extra").has("priority")) {
            priority = finding.path("extra").get("priority").asText();
        } else if (finding.path("extra").has("ml_priority")) {
            priority = finding.path("extra").get("ml_priority").asText();
        }
        v.setPriority(priority != null ? priority : "P2");

        return v;
    }

    private Finding toFinding(Scan scan, JsonNode finding) {
        JsonNode extra = finding.path("extra");
        Finding savedFinding = new Finding();
        savedFinding.setScan(scan);
        savedFinding.setRuleId(finding.path("check_id").asText("GENERIC-001"));
        savedFinding.setTitle(extra.path("message").asText(finding.path("check_name").asText(
                finding.path("check_id").asText("Security Finding"))));
        savedFinding.setFilePath(finding.path("path").asText(finding.path("file_abs_path").asText("unknown")));
        savedFinding.setLineNumber(finding.path("start").path("line").asInt(0));
        savedFinding.setSeverity(extra.path("severity").asText("MEDIUM").toUpperCase());
        savedFinding.setCodeSnippet(extra.path("lines").asText(null));
        if (finding.has("is_reachable")) {
            savedFinding.setIsReachable(finding.path("is_reachable").asBoolean());
        } else if (extra.has("reachable")) {
            savedFinding.setIsReachable(extra.path("reachable").asBoolean());
        } else if (extra.has("is_reachable")) {
            savedFinding.setIsReachable(extra.path("is_reachable").asBoolean());
        } else if (extra.has("reachability")) {
            savedFinding.setIsReachable(isReachableStatus(extra.path("reachability").asText()));
            savedFinding.setReachabilityStatus(extra.path("reachability").asText());
        }
        String priority = finding.path("priority").asText(extra.path("priority").asText(null));
        savedFinding.setPriority(priority);
        return savedFinding;
    }

    private ScanJobResponse toJobResponse(Scan scan) {
        Long projId = scan.getProject() != null ? scan.getProject().getId() : (scan.getRepository() != null ? scan.getRepository().getId() : null);
        return ScanJobResponse.builder()
                .id(scan.getId())
                .projectId(projId)
                .commitSha(scan.getCommitSha())
                .branch(scan.getBranch())
                .changedFiles(scan.getChangedFilePaths() == null || scan.getChangedFilePaths().isBlank()
                        ? List.of() : List.of(scan.getChangedFilePaths().split("\\n")))
                .status(scan.getStatus().name())
                .errorMessage(scan.getErrorMessage())
                .progress(scan.getProgress())
                .createdAt(scan.getCreatedAt())
                .completedAt(scan.getCompletedAt())
                .build();
    }
}
