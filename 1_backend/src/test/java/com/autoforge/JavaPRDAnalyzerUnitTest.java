package com.autoforge;

import com.autoforge.analyzer.dynamic.CorrelationEngine;
import com.autoforge.analyzer.graph.CrossRepoGraphBuilder;
import com.autoforge.analyzer.iac.IaCAnalyzer;
import com.autoforge.analyzer.privacy.ZKProofGenerator;
import com.autoforge.analyzer.remediation.RemediationEngine;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class JavaPRDAnalyzerUnitTest {

    @Test
    void testCrossRepoGraphBuilderBlastRadius() {
        CrossRepoGraphBuilder builder = new CrossRepoGraphBuilder();
        builder.addApiDependency("auth-service", "user-service", "/api/v1/users");
        builder.addApiDependency("user-service", "payment-service", "/api/v1/charges");
        builder.addApiDependency("auth-service", "notification-service", "/api/v1/notify");

        List<String> blastRadius = builder.findBlastRadius("auth-service");
        assertTrue(blastRadius.contains("user-service"));
        assertTrue(blastRadius.contains("payment-service"));
        assertTrue(blastRadius.contains("notification-service"));
    }

    @Test
    void testRemediationEngineSqlFixAndDiff() {
        RemediationEngine engine = new RemediationEngine();
        String original = "public void find(String id) {\n    executeQuery(\"SELECT * FROM users WHERE id = \" + id);\n}";
        String fixed = engine.generateSqlFix(original, 2, "id");

        assertTrue(fixed.contains("prepareStatement"));
        assertTrue(fixed.contains("setString(1, id)"));

        String diff = engine.generateUnifiedDiff(original, fixed, "UserService.java");
        assertTrue(diff.contains("--- a/UserService.java"));
        assertTrue(diff.contains("+++ b/UserService.java"));
        assertTrue(diff.contains("-    executeQuery"));
        assertTrue(diff.contains("+    prepareStatement"));
    }

    @Test
    void testZKProofGeneratorCommitment() {
        ZKProofGenerator zk = new ZKProofGenerator();
        String scanResults = "{\"findings\":[{\"rule\":\"SEC-001\"}]}";
        String salt = "super-secret-salt-123";

        String commitment = zk.generateScanCommitment(scanResults, salt);
        assertNotNull(commitment);
        assertEquals(64, commitment.length());

        assertTrue(zk.verifyScanCommitment(scanResults, salt, commitment));
        assertFalse(zk.verifyScanCommitment(scanResults, "wrong-salt", commitment));
    }

    @Test
    void testCorrelationEngineMatching() {
        CorrelationEngine engine = new CorrelationEngine();
        List<Map<String, Object>> events = List.of(
                Map.of("line", 42, "executed", true, "service", "web"),
                Map.of("line", 99, "executed", false, "service", "cron")
        );

        assertTrue(engine.verifyVulnerability(42, events));
        assertFalse(engine.verifyVulnerability(99, events));
        assertFalse(engine.verifyVulnerability(100, events));
    }

    @Test
    void testIaCAnalyzerPrivilegedK8sAndDockerfile() {
        IaCAnalyzer analyzer = new IaCAnalyzer();

        String k8sYaml = """
                apiVersion: apps/v1
                kind: Deployment
                metadata:
                  name: vulnerable-pod
                spec:
                  template:
                    spec:
                      containers:
                        - name: root-container
                          image: alpine:latest
                          securityContext:
                            privileged: true
                """;

        List<Map<String, Object>> k8sIssues = analyzer.auditK8sManifest(k8sYaml);
        assertEquals(1, k8sIssues.size());
        assertEquals("IAC-K8S-001", k8sIssues.get(0).get("rule_id"));
        assertEquals("CRITICAL", k8sIssues.get(0).get("severity"));

        String dockerfile = """
                FROM ubuntu:22.04
                RUN apt-get update
                CMD ["app"]
                """;
        List<Map<String, Object>> dockerIssues = analyzer.auditDockerfile(dockerfile);
        assertEquals(1, dockerIssues.size());
        assertEquals("DOCKER-001", dockerIssues.get(0).get("rule_id"));
    }
}
