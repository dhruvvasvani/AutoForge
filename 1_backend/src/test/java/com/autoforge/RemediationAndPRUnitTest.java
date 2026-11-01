package com.autoforge;

import com.autoforge.controller.RemediationController;
import com.autoforge.dto.PullRequestResponseDto;
import com.autoforge.dto.RemediationGenerateResponse;
import com.autoforge.dto.RemediationPreviewResponse;
import com.autoforge.entity.Finding;
import com.autoforge.entity.Fix;
import com.autoforge.entity.Project;
import com.autoforge.entity.PullRequest;
import com.autoforge.entity.Scan;
import com.autoforge.entity.User;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.FixRepository;
import com.autoforge.repository.PullRequestRepository;
import com.autoforge.service.AuditLogService;
import com.autoforge.service.PullRequestService;
import com.autoforge.service.RemediationService;
import com.autoforge.service.LlmRemediationClient;
import com.autoforge.service.GitHubPatchPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@ExtendWith(MockitoExtension.class)
public class RemediationAndPRUnitTest {

    @Mock
    private FindingRepository findingRepository;
    @Mock
    private FixRepository fixRepository;
    @Mock
    private PullRequestRepository pullRequestRepository;
    @Mock
    private AuditLogService auditLogService;
    @Mock
    private LlmRemediationClient llmRemediationClient;
    @Mock
    private GitHubPatchPublisher patchPublisher;

    private RemediationService remediationService;
    private PullRequestService pullRequestService;
    private RemediationController remediationController;

    @BeforeEach
    void setUp() {
        remediationService = new RemediationService(findingRepository, fixRepository, auditLogService, llmRemediationClient);
        pullRequestService = new PullRequestService(fixRepository, pullRequestRepository, auditLogService, patchPublisher);
        remediationController = new RemediationController(remediationService, pullRequestService);
    }

    @Test
    void testPreviewRemediationGeneratesUnifiedDiff() {
        Finding finding = new Finding();
        finding.setId(10L);
        finding.setFilePath("src/main/java/UserRepo.java");
        finding.setLineNumber(20);
        finding.setCodeSnippet("executeQuery(\"SELECT * FROM users WHERE id = \" + id);");
        finding.setIsReachable(true);
        setFindingOwner(finding);

        when(findingRepository.findById(10L)).thenReturn(Optional.of(finding));
        when(llmRemediationClient.generatePatch(finding))
                .thenReturn("--- a/src/main/java/UserRepo.java\n+++ b/src/main/java/UserRepo.java\n@@ -1 +1 @@\n-old\n+new");

        ResponseEntity<RemediationPreviewResponse> response = remediationController.previewRemediation(10L, authenticatedOwner());
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().getUnifiedDiff().contains("--- a/src/main/java/UserRepo.java"));
        assertTrue(response.getBody().getUnifiedDiff().contains("+++ b/src/main/java/UserRepo.java"));
    }

    @Test
    void testGenerateFixPersistsAndLogsAudit() {
        Finding finding = new Finding();
        finding.setId(15L);
        finding.setFilePath("src/main/java/OrderRepo.java");
        finding.setLineNumber(30);
        finding.setCodeSnippet("unsafe();");
        finding.setIsReachable(true);
        setFindingOwner(finding);

        when(findingRepository.findById(15L)).thenReturn(Optional.of(finding));
        when(llmRemediationClient.generatePatch(finding))
                .thenReturn("--- a/src/main/java/OrderRepo.java\n+++ b/src/main/java/OrderRepo.java\n@@ -1 +1 @@\n-old\n+new");
        when(llmRemediationClient.getConfiguredModel()).thenReturn("test-model");
        when(fixRepository.save(any(Fix.class))).thenAnswer(invocation -> {
            Fix f = invocation.getArgument(0);
            f.setId(100L);
            return f;
        });

        ResponseEntity<RemediationGenerateResponse> response = remediationController.generateRemediation(15L, authenticatedOwner());
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(100L, response.getBody().getId());
        assertEquals("GENERATED", response.getBody().getStatus());

        verify(auditLogService, times(1)).log(eq("FIX_GENERATED"), anyString());
    }

    @Test
    void prdFixGenerationRouteUsesTheAuthenticatedRemediationFlow() {
        Finding finding = new Finding();
        finding.setId(16L);
        finding.setFilePath("src/main/java/OrderRepo.java");
        finding.setLineNumber(30);
        finding.setIsReachable(true);
        setFindingOwner(finding);
        when(findingRepository.findById(16L)).thenReturn(Optional.of(finding));
        when(llmRemediationClient.generatePatch(finding))
                .thenReturn("--- a/src/main/java/OrderRepo.java\n+++ b/src/main/java/OrderRepo.java\n@@ -1 +1 @@\n-old\n+new");
        when(llmRemediationClient.getConfiguredModel()).thenReturn("test-model");
        when(fixRepository.save(any(Fix.class))).thenAnswer(invocation -> {
            Fix fix = invocation.getArgument(0);
            fix.setId(101L);
            return fix;
        });

        ResponseEntity<RemediationGenerateResponse> response =
                remediationController.generateFix(16L, authenticatedOwner());

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(16L, response.getBody().getFindingId());
        assertEquals("GENERATED", response.getBody().getStatus());
    }

    @Test
    void testApproveAndRejectFix() {
        Fix fix = new Fix();
        fix.setId(50L);
        fix.setStatus("PENDING");
        Finding finding = new Finding();
        setFindingOwner(finding);
        fix.setFinding(finding);

        when(fixRepository.findById(50L)).thenReturn(Optional.of(fix));
        when(fixRepository.save(any(Fix.class))).thenAnswer(invocation -> invocation.getArgument(0));

        var authentication = authenticatedOwner();
        ResponseEntity<Map<String, Object>> approveResp = remediationController.approveFix(50L, authentication);
        assertEquals("APPROVED", approveResp.getBody().get("status"));
        verify(auditLogService, times(1)).log(eq("FIX_APPROVED"), anyString());

        ResponseEntity<Map<String, Object>> rejectResp = remediationController.rejectFix(50L, authentication);
        assertEquals("REJECTED", rejectResp.getBody().get("status"));
        verify(auditLogService, times(1)).log(eq("FIX_REJECTED"), anyString());
    }

    @Test
    void testCreatePullRequestPreventsDuplicates() {
        User owner = new User();
        owner.setEmail("owner@example.com");
        Project project = new Project();
        project.setRepoUrl("https://github.com/acme/demo");
        project.setUser(owner);
        Scan scan = new Scan();
        scan.setProject(project);
        scan.setBranch("main");
        Finding finding = new Finding();
        finding.setId(19L);
        finding.setScan(scan);
        finding.setTitle("Unsafe query");
        Fix fix = new Fix();
        fix.setId(70L);
        fix.setFinding(finding);
        fix.setFilePath("src/Dao.java");
        fix.setSuggestedPatch("--- a/src/Dao.java\n+++ b/src/Dao.java\n@@ -1 +1 @@\n-old\n+new");
        fix.setStatus("APPROVED");

        PullRequest pr = new PullRequest();
        pr.setId(88L);
        pr.setFix(fix);
        pr.setGithubPrNumber(170);
        pr.setGithubPrUrl("https://github.com/autoforge/repo/pull/170");
        pr.setStatus("OPEN");

        when(fixRepository.findById(70L)).thenReturn(Optional.of(fix));
        when(patchPublisher.publish(fix)).thenReturn(new GitHubPatchPublisher.PublishedPullRequest(
                "acme/demo", "security/autoforge-fix-70", 170,
                "https://github.com/acme/demo/pull/170", "OPEN"));
        when(pullRequestRepository.findByFixId(70L))
                .thenReturn(Collections.emptyList())
                .thenReturn(List.of(pr));
        when(pullRequestRepository.save(any(PullRequest.class))).thenReturn(pr);

        var authentication = new UsernamePasswordAuthenticationToken("owner@example.com", null);
        ResponseEntity<PullRequestResponseDto> resp1 = remediationController.createPullRequest(70L, authentication);
        assertEquals(HttpStatus.CREATED, resp1.getStatusCode());
        assertEquals(170, resp1.getBody().getGithubPrNumber());

        ResponseEntity<PullRequestResponseDto> resp2 = remediationController.createPullRequest(70L, authentication);
        assertEquals(170, resp2.getBody().getGithubPrNumber());
        verify(pullRequestRepository, times(1)).save(any());
        verify(patchPublisher, times(1)).publish(fix);
    }

    @Test
    void doesNotPushUnapprovedFix() {
        User owner = new User();
        owner.setEmail("owner@example.com");
        Project project = new Project();
        project.setUser(owner);
        Scan scan = new Scan();
        scan.setProject(project);
        Finding finding = new Finding();
        finding.setScan(scan);
        Fix fix = new Fix();
        fix.setId(80L);
        fix.setFinding(finding);
        fix.setStatus("GENERATED");
        when(fixRepository.findById(80L)).thenReturn(Optional.of(fix));
        when(pullRequestRepository.findByFixId(80L)).thenReturn(Collections.emptyList());

        assertThrows(com.autoforge.exception.ApiException.class,
                () -> pullRequestService.createPullRequest(80L, "owner@example.com"));
        verifyNoInteractions(patchPublisher);
    }

    private UsernamePasswordAuthenticationToken authenticatedOwner() {
        return new UsernamePasswordAuthenticationToken("owner@example.com", null);
    }

    private void setFindingOwner(Finding finding) {
        User owner = new User();
        owner.setEmail("owner@example.com");
        Project project = new Project();
        project.setUser(owner);
        Scan scan = new Scan();
        scan.setProject(project);
        finding.setScan(scan);
    }
}
