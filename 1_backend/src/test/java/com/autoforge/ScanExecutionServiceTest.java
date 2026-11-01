package com.autoforge;

import com.autoforge.dto.ScanJobResponse;
import com.autoforge.entity.Project;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.entity.User;
import com.autoforge.repository.ScanRepository;
import com.autoforge.service.ScanExecutionService;
import com.autoforge.service.ScanProcessWorker;
import com.autoforge.service.ScanService;
import com.autoforge.service.ScanSourceStorageService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ScanExecutionServiceTest {
    @Mock
    private ScanRepository scanRepository;
    @Mock
    private ScanSourceStorageService storageService;
    @Mock
    private ScanProcessWorker scanProcessWorker;
    @Mock
    private ScanService scanService;

    @Test
    void startsQueuedScanAndDispatchesWorker() throws Exception {
        Scan scan = new Scan();
        scan.setId(42L);
        scan.setSourcePath("C:\\autoforge\\uploads\\42\\source");
        scan.setStatus(ScanStatus.QUEUED);
        Project project = new Project();
        User user = new User();
        user.setEmail("owner@example.com");
        project.setUser(user);
        scan.setProject(project);
        when(scanRepository.findById(42L)).thenReturn(Optional.of(scan));
        when(storageService.validateSourceDirectory(scan.getSourcePath()))
                .thenReturn(Path.of("C:\\autoforge\\uploads\\42\\source"));
        when(scanRepository.save(any(Scan.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(scanRepository.claimQueuedScan(eq(42L), any())).thenReturn(1);
        when(scanService.getScanJob(42L)).thenReturn(ScanJobResponse.builder().id(42L).status("RUNNING").build());

        ScanExecutionService service = new ScanExecutionService(scanRepository, storageService, scanProcessWorker, scanService);
        ScanJobResponse response = service.startScan(42L, "owner@example.com");

        assertEquals("RUNNING", response.getStatus());
        assertEquals(ScanStatus.RUNNING, scan.getStatus());
        assertNotNull(scan.getStartedAt());
        verify(scanProcessWorker).execute(42L, "C:\\autoforge\\uploads\\42\\source");
    }

    @Test
    void refusesToStartScanMoreThanOnce() {
        Scan scan = new Scan();
        scan.setId(42L);
        scan.setStatus(ScanStatus.RUNNING);
        when(scanRepository.findById(42L)).thenReturn(Optional.of(scan));

        ScanExecutionService service = new ScanExecutionService(scanRepository, storageService, scanProcessWorker, scanService);

        assertThrows(com.autoforge.exception.ApiException.class, () -> service.startScan(42L, "owner@example.com"));
        verifyNoInteractions(scanProcessWorker);
    }
}
