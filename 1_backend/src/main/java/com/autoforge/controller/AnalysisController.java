package com.autoforge.controller;

import com.autoforge.analyzer.dynamic.CorrelationEngine;
import com.autoforge.analyzer.graph.CrossRepoGraphBuilder;
import com.autoforge.analyzer.iac.IaCAnalyzer;
import com.autoforge.analyzer.privacy.ZKProofGenerator;
import com.autoforge.entity.Finding;
import com.autoforge.repository.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequiredArgsConstructor
public class AnalysisController {
    private final CrossRepoGraphBuilder crossRepoGraphBuilder;
    private final ZKProofGenerator zkProofGenerator;
    private final CorrelationEngine correlationEngine;
    private final IaCAnalyzer iacAnalyzer;
    private final FindingRepository findingRepository;

    private final Map<Long, List<Map<String, Object>>> runtimeEventsStore = new ConcurrentHashMap<>();

    @PostMapping("/api/v1/graph/rebuild")
    public ResponseEntity<Map<String, Object>> rebuildGraph(@RequestBody(required = false) Map<String, Object> payload) {
        if (payload != null && payload.containsKey("service") && payload.containsKey("dependencies")) {
            String service = String.valueOf(payload.get("service"));
            @SuppressWarnings("unchecked")
            List<Map<String, String>> deps = (List<Map<String, String>>) payload.get("dependencies");
            for (Map<String, String> dep : deps) {
                crossRepoGraphBuilder.addApiDependency(service, dep.get("target"), dep.get("endpoint"));
            }
        } else {
            crossRepoGraphBuilder.addApiDependency("frontend-service", "auth-service", "/api/v1/auth/login");
            crossRepoGraphBuilder.addApiDependency("auth-service", "database-service", "jdbc:postgresql");
            crossRepoGraphBuilder.addApiDependency("frontend-service", "scan-service", "/api/v1/scans/trigger");
            crossRepoGraphBuilder.addApiDependency("scan-service", "redis-service", "autoforge:scan_jobs");
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "REBUILT");
        response.put("nodes_count", crossRepoGraphBuilder.getServiceNodes().size());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/v1/graph/blast-radius")
    public ResponseEntity<Map<String, Object>> getBlastRadius(@RequestParam(name = "service", defaultValue = "auth-service") String service) {
        List<String> affected = crossRepoGraphBuilder.findBlastRadius(service);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("source_service", service);
        response.put("blast_radius", affected);
        response.put("total_affected", affected.size());
        return ResponseEntity.ok(response);
    }

    @GetMapping({"/api/v1/graph/dependencies", "/api/v1/graph/call-path"})
    public ResponseEntity<Map<String, Object>> getGraphDependencies() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("nodes", crossRepoGraphBuilder.getServiceNodes());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/api/v1/privacy/commit")
    public ResponseEntity<Map<String, Object>> createPrivacyCommitment(@RequestBody Map<String, String> request) {
        String scanResults = request.getOrDefault("scan_results", "{}");
        String secretSalt = request.getOrDefault("secret_salt", "autoforge-default-salt");
        Map<String, Object> proof = zkProofGenerator.generateProofMetadata(scanResults, secretSalt);
        return ResponseEntity.ok(proof);
    }

    @PostMapping("/api/v1/privacy/verify")
    public ResponseEntity<Map<String, Object>> verifyPrivacyCommitment(@RequestBody Map<String, String> request) {
        String scanResults = request.getOrDefault("scan_results", "{}");
        String secretSalt = request.getOrDefault("secret_salt", "autoforge-default-salt");
        String commitment = request.getOrDefault("commitment", "");
        boolean valid = zkProofGenerator.verifyScanCommitment(scanResults, secretSalt, commitment);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("valid", valid);
        response.put("commitment", commitment);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/api/v1/runtime/events")
    public ResponseEntity<Map<String, Object>> ingestRuntimeEvents(@RequestBody Map<String, Object> payload) {
        Long scanId = payload.containsKey("scan_id") ? Long.valueOf(String.valueOf(payload.get("scan_id"))) : 1L;
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> events = (List<Map<String, Object>>) payload.getOrDefault("events", Collections.emptyList());

        runtimeEventsStore.computeIfAbsent(scanId, k -> new ArrayList<>()).addAll(events);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "RECORDED");
        response.put("scan_id", scanId);
        response.put("events_count", events.size());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/v1/scans/{scanId}/runtime-correlation")
    public ResponseEntity<Map<String, Object>> getRuntimeCorrelation(@PathVariable("scanId") Long scanId) {
        List<Map<String, Object>> runtimeEvents = runtimeEventsStore.getOrDefault(scanId, Collections.emptyList());
        List<Finding> findings = findingRepository.findByScanId(scanId);

        List<Map<String, Object>> correlated = new ArrayList<>();
        int confirmedCount = 0;
        for (Finding f : findings) {
            boolean isConfirmed = correlationEngine.verifyVulnerability(f.getLineNumber(), runtimeEvents);
            if (isConfirmed) confirmedCount++;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("finding_id", f.getId());
            item.put("rule_id", f.getRuleId());
            item.put("line_number", f.getLineNumber());
            item.put("runtime_confirmed", isConfirmed);
            correlated.add(item);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("scan_id", scanId);
        response.put("total_findings", findings.size());
        response.put("runtime_confirmed_count", confirmedCount);
        response.put("findings", correlated);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/api/v1/analysis/iac")
    public ResponseEntity<Map<String, Object>> analyzeIaC(@RequestBody Map<String, String> request) {
        String manifestType = request.getOrDefault("manifest_type", "k8s");
        String content = request.getOrDefault("content", "");

        List<Map<String, Object>> findings;
        if ("dockerfile".equalsIgnoreCase(manifestType)) {
            findings = iacAnalyzer.auditDockerfile(content);
        } else {
            findings = iacAnalyzer.auditK8sManifest(content);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "COMPLETED");
        response.put("manifest_type", manifestType);
        response.put("findings_count", findings.size());
        response.put("findings", findings);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/v1/scans/{scanId}/iac-findings")
    public ResponseEntity<Map<String, Object>> getScanIaCFindings(@PathVariable("scanId") Long scanId) {
        List<Finding> findings = findingRepository.findByScanId(scanId).stream()
                .filter(f -> f.getRuleId() != null && (f.getRuleId().startsWith("IAC") || f.getRuleId().startsWith("DOCKER") || f.getRuleId().startsWith("CKV")))
                .toList();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("scan_id", scanId);
        response.put("iac_findings_count", findings.size());
        response.put("findings", findings);
        return ResponseEntity.ok(response);
    }
}
