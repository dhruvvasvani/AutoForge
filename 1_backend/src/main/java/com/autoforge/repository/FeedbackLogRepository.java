package com.autoforge.repository;

import com.autoforge.entity.FeedbackLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FeedbackLogRepository extends JpaRepository<FeedbackLog, Long> {
    List<FeedbackLog> findByUserIdOrderByCreatedAtAsc(Long userId);
}
