package com.autoforge.controller;

// Week 7-8 deliverable: Admin Panel APIs.
import com.autoforge.dto.AdminUserResponse;
import com.autoforge.dto.PlanRequestResponse;
import com.autoforge.dto.UpdateUserRoleRequest;
import com.autoforge.dto.UpdateUserLimitRequest;
import com.autoforge.dto.FindingFeedbackReviewRequest;
import com.autoforge.dto.FindingFeedbackResponse;
import com.autoforge.dto.MarkFeedbackTrainedRequest;
import com.autoforge.entity.FindingFeedback;
import com.autoforge.entity.UserStatus;
import com.autoforge.service.AdminService;
import com.autoforge.service.FindingFeedbackService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;
    private final FindingFeedbackService feedbackService;

    @GetMapping("/users")
    public ResponseEntity<Page<AdminUserResponse>> listUsers(Pageable pageable) {
        return ResponseEntity.ok(adminService.listUsers(pageable));
    }

    @PatchMapping("/users/{id}/status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AdminUserResponse> setStatus(@PathVariable Long id, @RequestParam UserStatus status) {
        return ResponseEntity.ok(adminService.setUserStatus(id, status));
    }

    @PatchMapping("/users/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AdminUserResponse> setRole(
            @PathVariable Long id,
            @Valid @RequestBody UpdateUserRoleRequest request) {
        return ResponseEntity.ok(adminService.setUserRole(id, request.getRole()));
    }

    @PatchMapping("/users/{id}/limit")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AdminUserResponse> changeLimit(@PathVariable Long id,
                                                          @Valid @RequestBody UpdateUserLimitRequest request) {
        return ResponseEntity.ok(adminService.changeUserPlan(id, request.getPlanName()));
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AdminUserResponse> deleteUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.deleteUser(id));
    }

    @GetMapping("/plan-requests")
    public ResponseEntity<List<PlanRequestResponse>> listPlanRequests(
            @RequestParam(required = false) String status) {
        return ResponseEntity.ok(adminService.listPlanRequests(status));
    }

    @PatchMapping("/plan-requests/{id}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PlanRequestResponse> approve(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.approvePlanRequest(id));
    }

    @PatchMapping("/plan-requests/{id}/reject")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PlanRequestResponse> reject(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.rejectPlanRequest(id));
    }

    @GetMapping("/mlops/feedback")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<FindingFeedbackResponse>> feedbackQueue(
            @RequestParam(defaultValue = "PENDING") FindingFeedback.ReviewStatus status,
            @RequestParam(defaultValue = "false") boolean untrainedOnly) {
        return ResponseEntity.ok(feedbackService.reviewQueue(status, untrainedOnly));
    }

    @GetMapping("/mlops/feedback/summary")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<java.util.Map<String, Object>> feedbackSummary() {
        long approved = feedbackService.approvedCount();
        return ResponseEntity.ok(java.util.Map.of(
                "approvedCount", approved,
                "retrainingThreshold", 500,
                "thresholdReached", approved >= 500
        ));
    }

    @PatchMapping("/mlops/feedback/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<FindingFeedbackResponse> reviewFeedback(
            @PathVariable Long id,
            Authentication authentication,
            @Valid @RequestBody FindingFeedbackReviewRequest request) {
        return ResponseEntity.ok(feedbackService.review(
                id,
                request.getStatus(),
                authentication.getName()
        ));
    }

    @PostMapping("/mlops/feedback/{id}/trained")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<FindingFeedbackResponse> markFeedbackTrained(@PathVariable Long id) {
        return ResponseEntity.ok(feedbackService.markTrained(id));
    }

    @PostMapping("/mlops/feedback/trained/batch")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<FindingFeedbackResponse>> markFeedbackBatchTrained(
            @Valid @RequestBody MarkFeedbackTrainedRequest request) {
        return ResponseEntity.ok(feedbackService.markTrained(request.feedbackIds()));
    }
}
