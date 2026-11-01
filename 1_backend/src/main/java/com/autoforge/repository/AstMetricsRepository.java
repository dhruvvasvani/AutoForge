package com.autoforge.repository;

import com.autoforge.entity.AstMetrics;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AstMetricsRepository extends JpaRepository<AstMetrics, Long> {
    Optional<AstMetrics> findByScanId(Long scanId);
}
