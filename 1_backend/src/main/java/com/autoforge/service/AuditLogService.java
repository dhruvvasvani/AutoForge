package com.autoforge.service;

import com.autoforge.entity.AuditLog;
import com.autoforge.entity.User;
import com.autoforge.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuditLogService {
    private final AuditLogRepository auditLogRepository;

    public void log(User actor, String action, String details) {
        AuditLog entry = new AuditLog();
        entry.setActor(actor);
        entry.setAction(action);
        entry.setDetails(details);
        entry.setCreatedAt(Instant.now());
        auditLogRepository.save(entry);
    }

    public void log(String action, String details) {
        log(null, action, details);
    }
}
