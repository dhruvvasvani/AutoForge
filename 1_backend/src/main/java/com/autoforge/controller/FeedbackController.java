package com.autoforge.controller;

import com.autoforge.dto.FeedbackRequest;
import com.autoforge.dto.FeedbackResponse;
import com.autoforge.service.FeedbackService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/feedback")
@RequiredArgsConstructor
public class FeedbackController {
    private final FeedbackService feedbackService;

    @GetMapping("/export")
    public ResponseEntity<java.util.List<FeedbackService.FeedbackExportRow>> export(
            Authentication authentication
    ) {
        return ResponseEntity.ok(feedbackService.exportForUser(authentication.getName()));
    }

    @PostMapping
    public ResponseEntity<FeedbackResponse> submit(
            Authentication authentication,
            @Valid @RequestBody FeedbackRequest request
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(feedbackService.submit(authentication.getName(), request));
    }
}
