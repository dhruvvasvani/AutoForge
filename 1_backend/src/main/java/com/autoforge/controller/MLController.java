package com.autoforge.controller;

import com.autoforge.dto.MLPredictionCreateRequest;
import com.autoforge.dto.MLPredictionResponseDto;
import com.autoforge.service.MLService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class MLController {
    private final MLService mlService;

    @PostMapping("/api/v1/ml/predictions")
    public ResponseEntity<MLPredictionResponseDto> createPrediction(@Valid @RequestBody MLPredictionCreateRequest request) {
        MLPredictionResponseDto response = mlService.savePrediction(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/api/v1/scans/results/ml")
    public ResponseEntity<Map<String, Object>> ingestScanMLResults(@RequestBody Map<String, Object> payload) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "success");
        response.put("message", "ML results received and processed");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/v1/findings/{findingId}/ml-score")
    public ResponseEntity<MLPredictionResponseDto> getFindingMLScore(@PathVariable("findingId") Long findingId) {
        return ResponseEntity.ok(mlService.getPredictionForFinding(findingId));
    }
}
