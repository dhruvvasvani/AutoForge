package com.autoforge.controller;

// Week 6 deliverable: user-facing plan request endpoint (User/Plan module).
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/plans")
@RequiredArgsConstructor
public class PlanController {

    private final UserRepository userRepository;
    private final PlanRepository planRepository;
    private final PlanRequestRepository planRequestRepository;

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
}
