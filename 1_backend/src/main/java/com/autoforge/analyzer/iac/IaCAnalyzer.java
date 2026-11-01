package com.autoforge.analyzer.iac;

import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

import java.util.*;

@Component
public class IaCAnalyzer {

    public List<Map<String, Object>> auditK8sManifest(String yamlContent) {
        List<Map<String, Object>> issues = new ArrayList<>();
        if (yamlContent == null || yamlContent.isBlank()) {
            return issues;
        }

        try {
            Yaml yaml = new Yaml();
            Iterable<Object> docs = yaml.loadAll(yamlContent);
            for (Object docObj : docs) {
                if (docObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> doc = (Map<String, Object>) docObj;
                    String kind = doc.get("kind") != null ? String.valueOf(doc.get("kind")) : null;

                    if (kind == null || "Deployment".equalsIgnoreCase(kind) || "Pod".equalsIgnoreCase(kind) || "StatefulSet".equalsIgnoreCase(kind) || "DaemonSet".equalsIgnoreCase(kind)) {
                        inspectSpec(doc, issues);
                    }
                }
            }
        } catch (Exception e) {
            Map<String, Object> parseError = new LinkedHashMap<>();
            parseError.put("rule_id", "IAC-PARSE-ERR");
            parseError.put("severity", "LOW");
            parseError.put("message", "Could not fully parse YAML manifest: " + e.getMessage());
            issues.add(parseError);
        }

        return issues;
    }

    public List<Map<String, Object>> auditDockerfile(String dockerfileContent) {
        List<Map<String, Object>> issues = new ArrayList<>();
        if (dockerfileContent == null || dockerfileContent.isBlank()) return issues;

        boolean hasUserDirective = false;
        String[] lines = dockerfileContent.split("\r?\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("USER ") && !trimmed.equalsIgnoreCase("USER root")) {
                hasUserDirective = true;
            }
            if ((trimmed.contains("curl") || trimmed.contains("wget")) && (trimmed.contains("| bash") || trimmed.contains("| sh"))) {
                Map<String, Object> issue = new LinkedHashMap<>();
                issue.put("rule_id", "DOCKER-002");
                issue.put("severity", "CRITICAL");
                issue.put("message", "Unsafe pipe-to-shell detected in build instruction: " + trimmed);
                issues.add(issue);
            }
        }

        if (!hasUserDirective) {
            Map<String, Object> issue = new LinkedHashMap<>();
            issue.put("rule_id", "DOCKER-001");
            issue.put("severity", "HIGH");
            issue.put("message", "Dockerfile does not define a non-root USER instruction.");
            issues.add(issue);
        }

        return issues;
    }

    @SuppressWarnings("unchecked")
    private void inspectSpec(Map<String, Object> doc, List<Map<String, Object>> issues) {
        Map<String, Object> spec = (Map<String, Object>) doc.get("spec");
        if (spec == null) return;

        Map<String, Object> template = (Map<String, Object>) spec.get("template");
        Map<String, Object> podSpec = template != null ? (Map<String, Object>) template.get("spec") : spec;
        if (podSpec == null) return;

        List<Object> containers = (List<Object>) podSpec.get("containers");
        if (containers == null) return;

        for (Object cObj : containers) {
            if (cObj instanceof Map) {
                Map<String, Object> container = (Map<String, Object>) cObj;
                String containerName = String.valueOf(container.get("name"));
                Map<String, Object> secCtx = (Map<String, Object>) container.get("securityContext");
                if (secCtx != null && Boolean.TRUE.equals(secCtx.get("privileged"))) {
                    Map<String, Object> issue = new LinkedHashMap<>();
                    issue.put("rule_id", "IAC-K8S-001");
                    issue.put("severity", "CRITICAL");
                    issue.put("message", String.format("Container '%s' runs with root privileges (privileged: true).", containerName));
                    issues.add(issue);
                }
            }
        }
    }
}
