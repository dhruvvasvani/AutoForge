package com.autoforge.controller;

import com.autoforge.dto.FindingFeedbackRequest;
import com.autoforge.dto.FindingFeedbackResponse;
import com.autoforge.service.FindingFeedbackService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/feedback")
@RequiredArgsConstructor
public class FindingFeedbackController {

    private final FindingFeedbackService feedbackService;

    @PostMapping
    public ResponseEntity<FindingFeedbackResponse> submit(
            Authentication authentication,
            @Valid @RequestBody FindingFeedbackRequest request
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(feedbackService.submit(authentication.getName(), request));
    }
}
