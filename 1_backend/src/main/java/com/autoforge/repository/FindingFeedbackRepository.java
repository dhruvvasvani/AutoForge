package com.autoforge.repository;

import com.autoforge.entity.FindingFeedback;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FindingFeedbackRepository extends JpaRepository<FindingFeedback, Long> {
    boolean existsByUserEmailAndFindingKey(String email, String findingKey);
    List<FindingFeedback> findTop1000ByReviewStatusOrderByCreatedAtAsc(
            FindingFeedback.ReviewStatus reviewStatus
    );
    List<FindingFeedback> findTop1000ByReviewStatusAndTrainedAtIsNullOrderByCreatedAtAsc(
            FindingFeedback.ReviewStatus reviewStatus
    );
    Optional<FindingFeedback> findByIdAndReviewStatus(
            Long id,
            FindingFeedback.ReviewStatus reviewStatus
    );
    long countByReviewStatus(FindingFeedback.ReviewStatus reviewStatus);
    long countByReviewStatusAndTrainedAtIsNull(FindingFeedback.ReviewStatus reviewStatus);
}
