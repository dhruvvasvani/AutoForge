package com.autoforge.repository;

import com.autoforge.entity.ScanMetrics;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ScanMetricsRepository extends JpaRepository<ScanMetrics, Long> {

    @Query("""
            SELECT metrics FROM ScanMetrics metrics
            WHERE metrics.user.id = :userId
            ORDER BY metrics.scanTimestamp DESC, metrics.id DESC
            """)
    List<ScanMetrics> findRecentByUserId(@Param("userId") Long userId, Pageable pageable);
}
