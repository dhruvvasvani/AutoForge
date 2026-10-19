package com.autoforge.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ScanResponse {
    private Long id;
    private String status;
    private String commitSha;
}
