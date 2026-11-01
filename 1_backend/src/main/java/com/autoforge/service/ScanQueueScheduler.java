package com.autoforge.service;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ScanQueueScheduler {
    private final ScanJobRedisWorker worker;

    @Scheduled(fixedDelayString = "${autoforge.queue.poll-interval-ms:1000}")
    public void pollQueue() {
        worker.processNextJob();
    }
}
