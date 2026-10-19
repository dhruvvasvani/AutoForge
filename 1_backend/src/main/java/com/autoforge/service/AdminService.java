package com.autoforge.service;

// Week 7-8 deliverable: Admin Panel APIs - user management + plan-request approval.
import com.autoforge.dto.AdminUserResponse;
import com.autoforge.dto.PlanRequestResponse;
import com.autoforge.entity.Plan;
import com.autoforge.entity.PlanRequest;
import com.autoforge.entity.User;
import com.autoforge.entity.UserStatus;
import com.autoforge.exception.ApiException;
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

    public Page<AdminUserResponse> listUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(this::toAdminUserResponse);
    }

    public AdminUserResponse setUserStatus(Long userId, UserStatus status) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        user.setStatus(status);
        user.setUpdatedAt(Instant.now());
        return toAdminUserResponse(userRepository.save(user));
    }

    public AdminUserResponse deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        userRepository.delete(user);
        return toAdminUserResponse(user);
    }

    public AdminUserResponse changeUserPlan(Long userId, String planName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        Plan plan = planRepository.findByName(planName)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "Unknown plan: " + planName));
        user.setPlan(plan);
        user.setUpdatedAt(Instant.now());
        return toAdminUserResponse(userRepository.save(user));
    }

    public List<PlanRequestResponse> listPlanRequests(String status) {
        List<PlanRequest> requests = status != null
                ? planRequestRepository.findByStatus(status)
                : planRequestRepository.findAll();
        return requests.stream().map(this::toPlanRequestResponse).toList();
    }

    public PlanRequestResponse approvePlanRequest(Long requestId) {
        PlanRequest request = planRequestRepository.findById(requestId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Plan request not found"));

        request.getUser().setPlan(request.getRequestedPlan());
        request.setStatus("APPROVED");
        request.setResolvedAt(Instant.now());
        planRequestRepository.save(request);
        userRepository.save(request.getUser());

        return toPlanRequestResponse(request);
    }

    public PlanRequestResponse rejectPlanRequest(Long requestId) {
        PlanRequest request = planRequestRepository.findById(requestId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Plan request not found"));

        request.setStatus("REJECTED");
        request.setResolvedAt(Instant.now());
        planRequestRepository.save(request);

        return toPlanRequestResponse(request);
    }

    private AdminUserResponse toAdminUserResponse(User user) {
        return new AdminUserResponse(
                user.getId(), user.getFullName(), user.getEmail(),
                user.getRole().name(), user.getStatus().name(),
                user.getPlan() != null ? user.getPlan().getName() : null
        );
    }

    private PlanRequestResponse toPlanRequestResponse(PlanRequest request) {
        return new PlanRequestResponse(
                request.getId(), request.getUser().getId(), request.getUser().getEmail(),
                request.getRequestedPlan().getName(), request.getStatus(), request.getCreatedAt()
        );
    }
}
