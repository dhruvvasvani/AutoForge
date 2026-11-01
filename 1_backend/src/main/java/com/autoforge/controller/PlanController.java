package com.autoforge.controller;

import com.autoforge.dto.PlanRequestResponse;
import com.autoforge.dto.PlanResponse;
import com.autoforge.entity.Plan;
import com.autoforge.entity.PlanRequest;
import com.autoforge.entity.User;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.PlanRepository;
import com.autoforge.repository.PlanRequestRepository;
import com.autoforge.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/plans")
@RequiredArgsConstructor
public class PlanController {
    private final UserRepository userRepository;
    private final PlanRepository planRepository;
    private final PlanRequestRepository planRequestRepository;

    @GetMapping
    public ResponseEntity<List<PlanResponse>> getAllPlans() {
        List<PlanResponse> plans = planRepository.findAll().stream()
                .map(p -> new PlanResponse(p.getId(), p.getName(), p.getMaxRepositories(), p.getMaxScansPerMonth()))
                .toList();
        return ResponseEntity.ok(plans);
    }

    @PostMapping("/request")
    public ResponseEntity<String> requestPlan(Authentication authentication, @RequestParam String planName) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        Plan plan = planRepository.findByName(planName)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "Unknown plan: " + planName));

        PlanRequest request = new PlanRequest();
        request.setUser(user);
        request.setRequestedPlan(plan);
        planRequestRepository.save(request);

        return ResponseEntity.ok("Plan request submitted - awaiting admin approval");
    }

    @GetMapping("/my-requests")
    public ResponseEntity<List<PlanRequestResponse>> getMyRequests(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        List<PlanRequestResponse> requests = planRequestRepository.findByUserIdOrderByCreatedAtDesc(user.getId())
                .stream()
                .map(r -> new PlanRequestResponse(r.getId(), r.getUser().getId(), r.getUser().getEmail(),
                        r.getRequestedPlan().getName(), r.getStatus(), r.getCreatedAt()))
                .toList();
        return ResponseEntity.ok(requests);
    }
}
