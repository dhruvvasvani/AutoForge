package com.autoforge.service;

import com.autoforge.dto.FindingFeedbackRequest;
import com.autoforge.dto.FindingFeedbackResponse;
import com.autoforge.entity.FindingFeedback;
import com.autoforge.entity.User;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.FindingFeedbackRepository;
import com.autoforge.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Transactional
public class FindingFeedbackService {

    private final FindingFeedbackRepository feedbackRepository;
    private final UserRepository userRepository;

    public FindingFeedbackResponse submit(String email, FindingFeedbackRequest request) {
        if (feedbackRepository.existsByUserEmailAndFindingKey(email, request.getFindingKey())) {
            throw new ApiException(HttpStatus.CONFLICT, "Feedback for this finding was already submitted");
        }
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        FindingFeedback feedback = new FindingFeedback();
        feedback.setUser(user);
        feedback.setFindingKey(request.getFindingKey().trim());
        feedback.setLabel(request.getLabel());
        feedback.setSourceSnippet(request.getSourceSnippet());
        feedback.setReason(request.getReason() == null ? "" : request.getReason().trim());
        try {
            return toResponse(feedbackRepository.saveAndFlush(feedback));
        } catch (DataIntegrityViolationException error) {
            throw new ApiException(HttpStatus.CONFLICT, "Feedback for this finding was already submitted");
        }
    }

    @Transactional(readOnly = true)
    public List<FindingFeedbackResponse> reviewQueue(
            FindingFeedback.ReviewStatus status,
            boolean untrainedOnly
    ) {
        List<FindingFeedback> entries = untrainedOnly
                ? feedbackRepository.findTop1000ByReviewStatusAndTrainedAtIsNullOrderByCreatedAtAsc(status)
                : feedbackRepository.findTop1000ByReviewStatusOrderByCreatedAtAsc(status);
        return entries
                .stream()
                .map(FindingFeedbackService::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public long approvedCount() {
        return feedbackRepository.countByReviewStatusAndTrainedAtIsNull(
                FindingFeedback.ReviewStatus.APPROVED
        );
    }

    public FindingFeedbackResponse review(
            Long feedbackId,
            FindingFeedback.ReviewStatus status,
            String reviewer
    ) {
        if (status == FindingFeedback.ReviewStatus.PENDING) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Review status must be APPROVED or REJECTED");
        }
        FindingFeedback feedback = feedbackRepository.findById(feedbackId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Feedback not found"));
        if (feedback.getReviewStatus() != FindingFeedback.ReviewStatus.PENDING) {
            throw new ApiException(HttpStatus.CONFLICT, "Feedback has already been reviewed");
        }
        feedback.setReviewStatus(status);
        feedback.setReviewedBy(reviewer);
        feedback.setReviewedAt(Instant.now());
        return toResponse(feedbackRepository.save(feedback));
    }

    public FindingFeedbackResponse markTrained(Long feedbackId) {
        FindingFeedback feedback = feedbackRepository.findByIdAndReviewStatus(
                        feedbackId,
                        FindingFeedback.ReviewStatus.APPROVED
                )
                .orElseThrow(() -> new ApiException(
                        HttpStatus.NOT_FOUND,
                        "Approved feedback not found"
                ));
        if (feedback.getTrainedAt() != null) {
            throw new ApiException(HttpStatus.CONFLICT, "Feedback was already used for a training run");
        }
        feedback.setTrainedAt(Instant.now());
        return toResponse(feedbackRepository.save(feedback));
    }

    public List<FindingFeedbackResponse> markTrained(List<Long> feedbackIds) {
        if (feedbackIds.size() != Set.copyOf(feedbackIds).size()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "feedbackIds must be unique");
        }
        List<FindingFeedback> feedback = feedbackRepository.findAllById(feedbackIds);
        if (feedback.size() != feedbackIds.size()
                || feedback.stream().anyMatch(item ->
                item.getReviewStatus() != FindingFeedback.ReviewStatus.APPROVED
                        || item.getTrainedAt() != null)) {
            throw new ApiException(
                    HttpStatus.CONFLICT,
                    "All feedback IDs must be approved and not previously trained"
            );
        }
        Instant trainedAt = Instant.now();
        feedback.forEach(item -> item.setTrainedAt(trainedAt));
        return feedbackRepository.saveAll(feedback)
                .stream()
                .map(FindingFeedbackService::toResponse)
                .toList();
    }

    private static FindingFeedbackResponse toResponse(FindingFeedback feedback) {
        return new FindingFeedbackResponse(
                feedback.getId(),
                feedback.getFindingKey(),
                feedback.getLabel(),
                feedback.getSourceSnippet(),
                feedback.getReason(),
                feedback.getReviewStatus(),
                feedback.getUser().getEmail(),
                feedback.getCreatedAt(),
                feedback.getReviewedBy(),
                feedback.getReviewedAt(),
                feedback.getTrainedAt()
        );
    }
}
