package com.autoforge.repository;

import com.autoforge.entity.PlanRequest;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PlanRequestRepository extends JpaRepository<PlanRequest, Long> {
    List<PlanRequest> findByStatus(String status);
}
