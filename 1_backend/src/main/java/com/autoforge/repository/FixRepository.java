package com.autoforge.repository;

import com.autoforge.entity.Fix;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FixRepository extends JpaRepository<Fix, Long> {
    List<Fix> findByVulnerabilityId(Long vulnerabilityId);
    List<Fix> findByFindingId(Long findingId);
    java.util.Optional<Fix> findTopByFindingIdOrderByCreatedAtDesc(Long findingId);
}
