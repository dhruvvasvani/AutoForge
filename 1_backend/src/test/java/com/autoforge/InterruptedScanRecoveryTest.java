package com.autoforge;

import com.autoforge.entity.Project;
import com.autoforge.entity.Scan;
import com.autoforge.repository.ScanRepository;
import com.autoforge.service.ScanExecutionService;
import com.autoforge.service.ScanProcessWorker;
import com.autoforge.service.ScanService;
import com.autoforge.service.ScanSourceStorageService;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class InterruptedScanRecoveryTest {
    @Test
    void reclaimsInterruptedLocalScanAndDispatchesItAgain() {
        ScanRepository scans = mock(ScanRepository.class);
        ScanSourceStorageService storage = mock(ScanSourceStorageService.class);
        ScanProcessWorker worker = mock(ScanProcessWorker.class);
        ScanService scanService = mock(ScanService.class);
        Scan scan = new Scan();
        scan.setId(71L);
        scan.setSourcePath("C:\\autoforge\\uploads\\scan-71");
        scan.setProject(new Project());
        when(scans.requeueStaleScan(eq(71L), any(Instant.class), anyString())).thenReturn(1);
        when(scans.findById(71L)).thenReturn(Optional.of(scan));
        when(scans.claimQueuedScan(eq(71L), any(Instant.class))).thenReturn(1);
        when(scans.save(any(Scan.class))).thenReturn(scan);

        ScanExecutionService service = new ScanExecutionService(scans, storage, worker, scanService);
        assertTrue(service.recoverInterruptedScan(71L, Instant.now().minusSeconds(2100)));

        verify(worker).execute(71L, "C:\\autoforge\\uploads\\scan-71");
    }

    @Test
    void doesNotRestartScanWhenItIsNotStaleOrAlreadyClaimed() {
        ScanRepository scans = mock(ScanRepository.class);
        ScanExecutionService service = new ScanExecutionService(scans,
                mock(ScanSourceStorageService.class), mock(ScanProcessWorker.class), mock(ScanService.class));
        when(scans.requeueStaleScan(eq(72L), any(Instant.class), anyString())).thenReturn(0);

        assertFalse(service.recoverInterruptedScan(72L, Instant.now()));
        verify(scans, never()).claimQueuedScan(anyLong(), any(Instant.class));
    }
}
