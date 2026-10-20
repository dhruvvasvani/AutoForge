package com.autoforge.repository;

import com.autoforge.entity.Fix;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface FixRepository extends JpaRepository<Fix, Long> {
    Optional<Fix> findFirstByVulnerabilityIdOrderByIdDesc(Long vulnerabilityId);
}