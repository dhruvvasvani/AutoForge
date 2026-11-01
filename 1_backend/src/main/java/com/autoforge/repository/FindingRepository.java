package com.autoforge.repository;

import com.autoforge.entity.Finding;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FindingRepository extends JpaRepository<Finding, Long> {
    List<Finding> findByScanId(Long scanId);
    long countByScanIdAndSeverityIgnoreCase(Long scanId, String severity);

    @Query("SELECT f FROM Finding f JOIN f.scan s WHERE s.project.id = :projectId " +
           "AND (:severity IS NULL OR f.severity = :severity) " +
           "AND (:ruleId IS NULL OR f.ruleId = :ruleId)")
    Page<Finding> findByProjectIdWithFilters(
            @Param("projectId") Long projectId,
            @Param("severity") String severity,
            @Param("ruleId") String ruleId,
            Pageable pageable
    );

    @Query("SELECT f FROM Finding f JOIN f.scan s WHERE s.project.id = :projectId")
    List<Finding> findAllByProjectId(@Param("projectId") Long projectId);
}
