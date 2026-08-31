package com.autoforge.controller;

// Week 7-8 deliverable: Admin Panel APIs.
import com.autoforge.dto.AdminUserResponse;
import com.autoforge.dto.PlanRequestResponse;
import com.autoforge.dto.UpdateUserLimitRequest;
import com.autoforge.entity.UserStatus;
import com.autoforge.service.AdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @GetMapping("/users")
    public ResponseEntity<Page<AdminUserResponse>> listUsers(Pageable pageable) {
        return ResponseEntity.ok(adminService.listUsers(pageable));
    }

    @PatchMapping("/users/{id}/status")
    public ResponseEntity<AdminUserResponse> setStatus(@PathVariable Long id, @RequestParam UserStatus status) {
        return ResponseEntity.ok(adminService.setUserStatus(id, status));
    }

    @PatchMapping("/users/{id}/limit")
    public ResponseEntity<AdminUserResponse> changeLimit(@PathVariable Long id,
                                                          @Valid @RequestBody UpdateUserLimitRequest request) {
        return ResponseEntity.ok(adminService.changeUserPlan(id, request.getPlanName()));
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<AdminUserResponse> deleteUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.deleteUser(id));
    }

    @GetMapping("/plan-requests")
    public ResponseEntity<List<PlanRequestResponse>> listPlanRequests(
            @RequestParam(required = false) String status) {
        return ResponseEntity.ok(adminService.listPlanRequests(status));
    }

    @PatchMapping("/plan-requests/{id}/approve")
    public ResponseEntity<PlanRequestResponse> approve(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.approvePlanRequest(id));
    }

    @PatchMapping("/plan-requests/{id}/reject")
    public ResponseEntity<PlanRequestResponse> reject(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.rejectPlanRequest(id));
    }
}
