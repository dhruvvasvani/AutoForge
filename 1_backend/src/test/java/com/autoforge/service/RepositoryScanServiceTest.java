package com.autoforge.service;

import com.autoforge.entity.Repository;
import com.autoforge.entity.Scan;
import com.autoforge.entity.User;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.RepositoryRepository;
import com.autoforge.repository.ScanRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RepositoryScanServiceTest {
    @Test
    void queuesLatestPublicRepositoryCommitForItsOwner() {
        RepositoryRepository repositories = mock(RepositoryRepository.class);
        ScanRepository scans = mock(ScanRepository.class);
        QueueService queue = mock(QueueService.class);
        GitHubRepositoryClient github = mock(GitHubRepositoryClient.class);
        User user = new User();
        user.setEmail("owner@example.com");
        Repository repository = new Repository();
        repository.setId(7L);
        repository.setGithubRepoFullName("owner/repo");
        repository.setUser(user);
        when(repositories.findById(7L)).thenReturn(Optional.of(repository));
        when(github.latestCommit("owner/repo"))
                .thenReturn(new GitHubRepositoryClient.LatestCommit("main", "a".repeat(40)));
        when(scans.save(any(Scan.class))).thenAnswer(invocation -> {
            Scan scan = invocation.getArgument(0);
            scan.setId(21L);
            return scan;
        });

        var response = new RepositoryScanService(repositories, scans, queue, github)
                .triggerLatestScan(7L, "owner@example.com");

        assertEquals(21L, response.getId());
        assertEquals("QUEUED", response.getStatus());
        assertEquals("main", response.getBranch());
        verify(queue).publishScanJob(21L, 7L, "https://github.com/owner/repo.git",
                "a".repeat(40), "main");
    }

    @Test
    void doesNotAllowAnotherUserToScanRepository() {
        RepositoryRepository repositories = mock(RepositoryRepository.class);
        User user = new User();
        user.setEmail("owner@example.com");
        Repository repository = new Repository();
        repository.setUser(user);
        when(repositories.findById(7L)).thenReturn(Optional.of(repository));
        GitHubRepositoryClient github = mock(GitHubRepositoryClient.class);
        RepositoryScanService service = new RepositoryScanService(
                repositories, mock(ScanRepository.class), mock(QueueService.class), github);

        ApiException error = assertThrows(ApiException.class,
                () -> service.triggerLatestScan(7L, "other@example.com"));

        assertEquals(403, error.getStatus().value());
        verifyNoInteractions(github);
    }
}
