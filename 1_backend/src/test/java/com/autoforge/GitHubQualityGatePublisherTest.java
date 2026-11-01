package com.autoforge;

import com.autoforge.entity.Project;
import com.autoforge.entity.Scan;
import com.autoforge.repository.ScanRepository;
import com.autoforge.service.GitHubCommitStatusClient;
import com.autoforge.service.GitHubQualityGatePublisher;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.mockito.Mockito.*;

class GitHubQualityGatePublisherTest {
    @Test
    void publishesGateStatusOnlyForScanVisibleToRequestingUser() {
        ScanRepository scans = mock(ScanRepository.class);
        GitHubCommitStatusClient client = mock(GitHubCommitStatusClient.class);
        Project project = new Project();
        project.setRepoUrl("https://github.com/acme/demo.git");
        Scan scan = new Scan();
        scan.setProject(project);
        scan.setCommitSha("0123456789abcdef0123456789abcdef01234567");
        when(scans.findVisibleScanById(71L, "owner@example.com")).thenReturn(Optional.of(scan));

        new GitHubQualityGatePublisher(scans, client).publish(
                71L, "owner@example.com", false, "Found reachable critical findings.");

        verify(client).publish("acme/demo", scan.getCommitSha(), false, "Found reachable critical findings.");
    }
}
