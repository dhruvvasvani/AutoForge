package com.autoforge.service;

import com.autoforge.entity.ScanStatus;
import com.autoforge.repository.ScanRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(name = "autoforge.java-scan-worker.enabled", havingValue = "true", matchIfMissing = false)
public class InterruptedScanRecovery {
    private final ScanRepository scanRepository;
    private final ScanExecutionService scanExecutionService;

    @Value("${autoforge.scanner.recovery-stale-after:PT35M}")
    private Duration staleAfter;

    @Scheduled(fixedDelayString = "${autoforge.scanner.recovery-poll-interval-ms:60000}")
    public void recoverStaleScans() {
        Instant staleBefore = Instant.now().minus(staleAfter);
        List<Long> scanIds = scanRepository.findTop100ByStatusInAndStartedAtBeforeOrderByStartedAtAsc(
                        List.of(ScanStatus.RUNNING, ScanStatus.PROCESSING), staleBefore)
                .stream()
                .map(scan -> scan.getId())
                .toList();
        for (Long scanId : scanIds) {
            try {
                if (scanExecutionService.recoverInterruptedScan(scanId, staleBefore)) {
                    log.warn("Restarted stale scan {} after worker interruption.", scanId);
                }
            } catch (RuntimeException ex) {
                log.error("Failed to recover stale scan {}: {}", scanId, ex.getMessage(), ex);
            }
        }
    }
}
