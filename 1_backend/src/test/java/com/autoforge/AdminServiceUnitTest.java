package com.autoforge;

import com.autoforge.dto.AuditLogResponse;
import com.autoforge.entity.AuditLog;
import com.autoforge.entity.User;
import com.autoforge.repository.AuditLogRepository;
import com.autoforge.repository.PlanRepository;
import com.autoforge.repository.PlanRequestRepository;
import com.autoforge.repository.UserRepository;
import com.autoforge.service.AdminService;
import com.autoforge.service.AuditLogService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminServiceUnitTest {
    @Mock
    private UserRepository userRepository;
    @Mock
    private PlanRepository planRepository;
    @Mock
    private PlanRequestRepository planRequestRepository;
    @Mock
    private AuditLogService auditLogService;
    @Mock
    private AuditLogRepository auditLogRepository;

    @InjectMocks
    private AdminService adminService;

    @Test
    void getAuditLogsReturnsPagedResults() {
        User user = new User();
        user.setEmail("actor@example.com");

        AuditLog log = new AuditLog();
        log.setId(10L);
        log.setActor(user);
        log.setAction("PROFILE_UPDATE");
        log.setDetails("Updated profile fields: fullName");
        log.setCreatedAt(Instant.now());

        Pageable pageable = PageRequest.of(0, 10);
        when(auditLogRepository.findAllByOrderByCreatedAtDesc(pageable))
                .thenReturn(new PageImpl<>(List.of(log), pageable, 1));

        Page<AuditLogResponse> response = adminService.getAuditLogs(pageable);

        assertEquals(1, response.getTotalElements());
        assertEquals("actor@example.com", response.getContent().get(0).getActorEmail());
        assertEquals("PROFILE_UPDATE", response.getContent().get(0).getAction());
    }
}
