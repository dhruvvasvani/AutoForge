package com.autoforge.service;

import com.autoforge.entity.CallTrace;
import com.autoforge.entity.Finding;
import com.autoforge.repository.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class SarifService {
    private final FindingRepository findingRepository;

    public Map<String, Object> generateSarifReport(Long scanId) {
        List<Finding> findings = findingRepository.findByScanId(scanId);

        List<Map<String, Object>> resultsList = new ArrayList<>();
        Map<String, Map<String, Object>> rulesMap = new LinkedHashMap<>();

        for (Finding f : findings) {
            String ruleId = f.getRuleId() != null ? f.getRuleId() : "SEC-GENERIC-001";
            String sev = f.getSeverity() != null ? f.getSeverity().toUpperCase() : "MEDIUM";
            String level = ("CRITICAL".equals(sev) || "HIGH".equals(sev)) ? "error" : "warning";

            rulesMap.computeIfAbsent(ruleId, rid -> {
                Map<String, Object> rule = new LinkedHashMap<>();
                rule.put("id", rid);
                rule.put("name", rid);
                Map<String, String> desc = new LinkedHashMap<>();
                desc.put("text", f.getTitle() != null ? f.getTitle() : "Security rule violation: " + rid);
                rule.put("shortDescription", desc);
                rule.put("defaultConfiguration", Map.of("level", level));
                return rule;
            });

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("ruleId", ruleId);
            result.put("level", level);

            Map<String, String> msg = new LinkedHashMap<>();
            msg.put("text", f.getTitle() != null ? f.getTitle() : "Vulnerability detected");
            result.put("message", msg);

            Map<String, Object> artifactLocation = new LinkedHashMap<>();
            artifactLocation.put("uri", f.getFilePath() != null ? f.getFilePath() : "unknown");

            Map<String, Object> region = new LinkedHashMap<>();
            region.put("startLine", f.getLineNumber() != null ? f.getLineNumber() : 1);

            Map<String, Object> physicalLocation = new LinkedHashMap<>();
            physicalLocation.put("artifactLocation", artifactLocation);
            physicalLocation.put("region", region);

            Map<String, Object> location = new LinkedHashMap<>();
            location.put("physicalLocation", physicalLocation);
            result.put("locations", Collections.singletonList(location));

            String fingerprintSource = (f.getFilePath() != null ? f.getFilePath() : "") + ":" +
                    (f.getLineNumber() != null ? f.getLineNumber() : 1) + ":" + ruleId;
            String fingerprintHash = sha256Hex(fingerprintSource);
            Map<String, String> partialFingerprints = new LinkedHashMap<>();
            partialFingerprints.put("primaryLocationLineHash", fingerprintHash);
            result.put("partialFingerprints", partialFingerprints);

            if (f.getCallTraces() != null && !f.getCallTraces().isEmpty()) {
                List<Map<String, Object>> threadFlowLocations = new ArrayList<>();
                for (CallTrace trace : f.getCallTraces()) {
                    Map<String, Object> traceLocation = new LinkedHashMap<>();
                    Map<String, Object> tracePhysLoc = new LinkedHashMap<>();
                    tracePhysLoc.put("artifactLocation", Map.of("uri", trace.getFilePath() != null ? trace.getFilePath() : "unknown"));
                    tracePhysLoc.put("region", Map.of("startLine", trace.getLineNumber() != null ? trace.getLineNumber() : 1));
                    traceLocation.put("location", Map.of(
                            "physicalLocation", tracePhysLoc,
                            "message", Map.of("text", trace.getSymbolName() != null ? trace.getSymbolName() : "step " + trace.getStepNumber())
                    ));
                    traceLocation.put("executionOrder", trace.getStepNumber() != null ? trace.getStepNumber() : 1);
                    threadFlowLocations.add(traceLocation);
                }
                Map<String, Object> threadFlow = new LinkedHashMap<>();
                threadFlow.put("locations", threadFlowLocations);
                Map<String, Object> codeFlow = new LinkedHashMap<>();
                codeFlow.put("threadFlows", Collections.singletonList(threadFlow));
                result.put("codeFlows", Collections.singletonList(codeFlow));
            }

            Map<String, Object> properties = new LinkedHashMap<>();
            properties.put("severity", sev);
            if (f.getCodeSnippet() != null) {
                properties.put("codeSnippet", f.getCodeSnippet());
            }
            result.put("properties", properties);

            resultsList.add(result);
        }

        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", "AutoForge");
        driver.put("version", "1.0.0");
        driver.put("informationUri", "https://github.com/autoforge/autoforge");
        driver.put("rules", new ArrayList<>(rulesMap.values()));

        Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("driver", driver);

        Map<String, Object> run = new LinkedHashMap<>();
        run.put("tool", tool);
        run.put("results", resultsList);

        Map<String, Object> sarif = new LinkedHashMap<>();
        sarif.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        sarif.put("version", "2.1.0");
        sarif.put("runs", Collections.singletonList(run));

        return sarif;
    }

    private String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return Integer.toHexString(input.hashCode());
        }
    }
}
