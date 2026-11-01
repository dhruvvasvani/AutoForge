package com.autoforge;

import com.autoforge.service.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ScanJobRedisWorkerTest {
    @Test
    void fallbackQueueStartsTheConfiguredRepositoryScan() {
        ScanExecutionService execution = mock(ScanExecutionService.class);
        ScanService scans = mock(ScanService.class);
        QueueService queue = new QueueService();
        queue.publishScanJob(41L, 8L, "https://github.com/acme/demo", "deadbeef1", "main");
        ScanJobRedisWorker worker = new ScanJobRedisWorker(execution, scans, queue);

        assertTrue(worker.processNextJob());
        verify(execution).startQueuedRepositoryScan(41L, "https://github.com/acme/demo", "deadbeef1", "main");
        verifyNoInteractions(scans);
        assertFalse(worker.processNextJob());
    }
}
