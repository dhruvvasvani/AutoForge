package com.autoforge.service;

import com.autoforge.dto.*;
import com.autoforge.entity.Plan;
import com.autoforge.entity.PlanRequest;
import com.autoforge.entity.User;
import com.autoforge.entity.UserStatus;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.AuditLogRepository;
import com.autoforge.repository.PlanRepository;
import com.autoforge.repository.PlanRequestRepository;
import com.autoforge.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminService {
    private final UserRepository userRepository;
    private final PlanRepository planRepository;
    private final PlanRequestRepository planRequestRepository;
    private final AuditLogService auditLogService;
    private final AuditLogRepository auditLogRepository;

    public Page<AdminUserResponse> listUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(this::toAdminUserResponse);
    }

    public AdminUserResponse setUserStatus(String adminEmail, Long userId, UserStatus status) {
        User admin = getUserOrThrow(adminEmail);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        user.setStatus(status);
        user.setUpdatedAt(Instant.now());
        User saved = userRepository.save(user);
        auditLogService.log(admin, "USER_STATUS_CHANGE", "Set status of " + user.getEmail() + " to " + status);
        return toAdminUserResponse(saved);
    }

    public AdminUserResponse deleteUser(String adminEmail, Long userId) {
        User admin = getUserOrThrow(adminEmail);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        userRepository.delete(user);
        auditLogService.log(admin, "USER_DELETE", "Deleted user " + user.getEmail());
        return toAdminUserResponse(user);
    }

    public AdminUserResponse changeUserPlan(String adminEmail, Long userId, String planName) {
        User admin = getUserOrThrow(adminEmail);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        Plan plan = planRepository.findByName(planName)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "Unknown plan: " + planName));
        user.setPlan(plan);
        user.setUpdatedAt(Instant.now());
        User saved = userRepository.save(user);
        auditLogService.log(admin, "PLAN_CHANGE", "Changed plan of " + user.getEmail() + " to " + planName);
        return toAdminUserResponse(saved);
    }

    public List<PlanRequestResponse> listPlanRequests(String status) {
        List<PlanRequest> requests = status != null ? planRequestRepository.findByStatus(status) : planRequestRepository.findAll();
        return requests.stream().map(this::toPlanRequestResponse).toList();
    }

    public PlanRequestResponse approvePlanRequest(String adminEmail, Long requestId) {
        User admin = getUserOrThrow(adminEmail);
        PlanRequest request = planRequestRepository.findById(requestId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Plan request not found"));
        request.getUser().setPlan(request.getRequestedPlan());
        request.setStatus("APPROVED");
        request.setResolvedAt(Instant.now());
        planRequestRepository.save(request);
        userRepository.save(request.getUser());
        auditLogService.log(admin, "PLAN_REQUEST_APPROVE", "Approved plan request for " + request.getUser().getEmail());
        return toPlanRequestResponse(request);
    }

    public PlanRequestResponse rejectPlanRequest(String adminEmail, Long requestId) {
        User admin = getUserOrThrow(adminEmail);
        PlanRequest request = planRequestRepository.findById(requestId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Plan request not found"));
        request.setStatus("REJECTED");
        request.setResolvedAt(Instant.now());
        planRequestRepository.save(request);
        auditLogService.log(admin, "PLAN_REQUEST_REJECT", "Rejected plan request for " + request.getUser().getEmail());
        return toPlanRequestResponse(request);
    }

    public Page<AuditLogResponse> getAuditLogs(Pageable pageable) {
        return auditLogRepository.findAllByOrderByCreatedAtDesc(pageable)
                .map(log -> new AuditLogResponse(log.getId(), log.getActor() != null ? log.getActor().getEmail() : "system",
                        log.getAction(), log.getDetails(), log.getCreatedAt()));
    }

    private User getUserOrThrow(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Admin user not found"));
    }

    private AdminUserResponse toAdminUserResponse(User user) {
        return new AdminUserResponse(user.getId(), user.getFullName(), user.getEmail(),
                user.getRole().name(), user.getStatus().name(),
                user.getPlan() != null ? user.getPlan().getName() : null);
    }

    private PlanRequestResponse toPlanRequestResponse(PlanRequest request) {
        return new PlanRequestResponse(request.getId(), request.getUser().getId(), request.getUser().getEmail(),
                request.getRequestedPlan().getName(), request.getStatus(), request.getCreatedAt());
    }
}
