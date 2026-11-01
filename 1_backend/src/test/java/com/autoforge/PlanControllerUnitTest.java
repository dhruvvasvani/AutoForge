package com.autoforge;

import com.autoforge.controller.PlanController;
import com.autoforge.dto.PlanRequestResponse;
import com.autoforge.dto.PlanResponse;
import com.autoforge.entity.Plan;
import com.autoforge.entity.PlanRequest;
import com.autoforge.entity.User;
import com.autoforge.repository.PlanRepository;
import com.autoforge.repository.PlanRequestRepository;
import com.autoforge.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PlanControllerUnitTest {
    @Mock
    private UserRepository userRepository;
    @Mock
    private PlanRepository planRepository;
    @Mock
    private PlanRequestRepository planRequestRepository;

    @InjectMocks
    private PlanController planController;

    @Test
    void getAllPlansReturnsList() {
        Plan plan = new Plan();
        plan.setId(1L);
        plan.setName("FREE");
        plan.setMaxRepositories(1);
        plan.setMaxScansPerMonth(10);

        when(planRepository.findAll()).thenReturn(List.of(plan));

        ResponseEntity<List<PlanResponse>> response = planController.getAllPlans();
        assertEquals(200, response.getStatusCode().value());
        assertEquals(1, response.getBody().size());
        assertEquals("FREE", response.getBody().get(0).getName());
    }

    @Test
    void getMyRequestsReturnsUserPlanRequests() {
        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn("user@example.com");

        User user = new User();
        user.setId(5L);
        user.setEmail("user@example.com");

        Plan requestedPlan = new Plan();
        requestedPlan.setName("PRO");

        PlanRequest request = new PlanRequest();
        request.setId(100L);
        request.setUser(user);
        request.setRequestedPlan(requestedPlan);
        request.setStatus("PENDING");
        request.setCreatedAt(Instant.now());

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(planRequestRepository.findByUserIdOrderByCreatedAtDesc(5L)).thenReturn(List.of(request));

        ResponseEntity<List<PlanRequestResponse>> response = planController.getMyRequests(auth);
        assertEquals(200, response.getStatusCode().value());
        assertEquals(1, response.getBody().size());
        assertEquals("PRO", response.getBody().get(0).getRequestedPlanName());
        assertEquals("PENDING", response.getBody().get(0).getStatus());
    }
}
