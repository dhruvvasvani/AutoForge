package com.autoforge.repository;

import com.autoforge.entity.MLPrediction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MLPredictionRepository extends JpaRepository<MLPrediction, Long> {
    Optional<MLPrediction> findTopByFindingIdOrderByCreatedAtDesc(Long findingId);
    java.util.List<MLPrediction> findByFindingScanId(Long scanId);
}
