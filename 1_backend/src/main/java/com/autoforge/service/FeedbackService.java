package com.autoforge.service;

import com.autoforge.dto.FeedbackRequest;
import com.autoforge.dto.FeedbackResponse;
import com.autoforge.entity.FeedbackLog;
import com.autoforge.entity.Finding;
import com.autoforge.entity.Fix;
import com.autoforge.entity.User;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.FeedbackLogRepository;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.FixRepository;
import com.autoforge.repository.UserRepository;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class FeedbackService {
    private final FeedbackLogRepository feedbackLogRepository;
    private final FindingRepository findingRepository;
    private final FixRepository fixRepository;
    private final UserRepository userRepository;

    @Transactional
    public FeedbackResponse submit(String userEmail, FeedbackRequest request) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found."));
        Finding finding = findingRepository.findById(request.getFindingId())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Finding not found."));
        if (!isOwnedBy(finding, user)) {
            throw new ApiException(HttpStatus.NOT_FOUND, "Finding not found.");
        }

        String action = request.getAction();
        Fix fix = null;
        if ("ACCEPT_PATCH".equals(action)) {
            if (request.getFixId() == null) {
                throw new ApiException(HttpStatus.BAD_REQUEST, "fix_id is required when accepting a patch.");
            }
            fix = fixRepository.findById(request.getFixId())
                    .filter(candidate -> candidate.getFinding() != null
                            && candidate.getFinding().getId().equals(finding.getId()))
                    .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Fix not found for this finding."));
            if (!"GENERATED".equals(fix.getStatus()) && !"APPROVED".equals(fix.getStatus())) {
                throw new ApiException(HttpStatus.CONFLICT, "Only a generated patch can be accepted.");
            }
            fix.setStatus("APPROVED");
            fixRepository.save(fix);
        } else if (request.getFixId() != null) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "fix_id is only valid when accepting a patch.");
        }

        FeedbackLog log = new FeedbackLog();
        log.setFinding(finding);
        log.setUser(user);
        log.setFix(fix);
        log.setFeedbackAction(action);
        log.setComment(request.getComment());
        FeedbackLog saved = feedbackLogRepository.save(log);

        return FeedbackResponse.builder()
                .id(saved.getId())
                .findingId(finding.getId())
                .fixId(fix == null ? null : fix.getId())
                .action(saved.getFeedbackAction())
                .comment(saved.getComment())
                .createdAt(saved.getCreatedAt())
                .build();
    }

    @Transactional(readOnly = true)
    public List<FeedbackExportRow> exportForUser(String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found."));
        return feedbackLogRepository.findByUserIdOrderByCreatedAtAsc(user.getId()).stream()
                .map(log -> FeedbackExportRow.builder()
                        .id(log.getId())
                        .findingId(log.getFinding().getId())
                        .fixId(log.getFix() == null ? null : log.getFix().getId())
                        .action(log.getFeedbackAction())
                        .comment(log.getComment())
                        .createdAt(log.getCreatedAt())
                        .build())
                .toList();
    }

    private boolean isOwnedBy(Finding finding, User user) {
        if (finding.getScan() == null) return false;
        if (finding.getScan().getProject() != null && finding.getScan().getProject().getUser() != null) {
            return user.getId().equals(finding.getScan().getProject().getUser().getId());
        }
        return finding.getScan().getRepository() != null
                && finding.getScan().getRepository().getUser() != null
                && user.getId().equals(finding.getScan().getRepository().getUser().getId());
    }

    @lombok.Getter
    @Builder
    public static class FeedbackExportRow {
        private Long id;
        private Long findingId;
        private Long fixId;
        private String action;
        private String comment;
        private java.time.Instant createdAt;
    }
}
