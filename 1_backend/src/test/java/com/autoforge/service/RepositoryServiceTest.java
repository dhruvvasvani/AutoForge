package com.autoforge.service;

import com.autoforge.entity.Repository;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.RepositoryRepository;
import com.autoforge.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RepositoryServiceTest {

    @Mock
    private RepositoryRepository repositoryRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private ScanService scanService;
    @Mock
    private GitHubLatestCommitResolver latestCommitResolver;

    private RepositoryService repositoryService;

    @BeforeEach
    void setUp() {
        repositoryService = new RepositoryService(
                repositoryRepository,
                userRepository,
                scanService,
                latestCommitResolver
        );
    }

    @Test
    void queuesScanForLatestCommitOfOwnedConnectedRepository() {
        Repository repository = new Repository();
        repository.setGithubRepoFullName("octo/demo");
        when(repositoryRepository.findByIdAndUserEmail(7L, "owner@example.com"))
                .thenReturn(Optional.of(repository));
        when(latestCommitResolver.resolve("octo/demo"))
                .thenReturn("0123456789abcdef0123456789abcdef01234567");
        Scan queued = new Scan();
        queued.setId(42L);
        queued.setCommitSha("0123456789abcdef0123456789abcdef01234567");
        queued.setStatus(ScanStatus.QUEUED);
        when(scanService.createScanJobFromPush(
                "octo/demo",
                "0123456789abcdef0123456789abcdef01234567",
                "manual"
        )).thenReturn(queued);

        Scan result = repositoryService.triggerRepositoryScan("owner@example.com", 7L);

        assertEquals(42L, result.getId());
        assertEquals(ScanStatus.QUEUED, result.getStatus());
        verify(latestCommitResolver).resolve("octo/demo");
        verify(scanService).createScanJobFromPush(
                "octo/demo",
                "0123456789abcdef0123456789abcdef01234567",
                "manual"
        );
    }

    @Test
    void doesNotFetchOrQueueRepositoryNotOwnedByUser() {
        when(repositoryRepository.findByIdAndUserEmail(7L, "other@example.com"))
                .thenReturn(Optional.empty());

        assertThrows(
                ApiException.class,
                () -> repositoryService.triggerRepositoryScan("other@example.com", 7L)
        );

        verify(latestCommitResolver, never()).resolve(org.mockito.ArgumentMatchers.anyString());
        verify(scanService, never()).createScanJobFromPush(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString()
        );
    }
}
