package com.autoforge.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Instant;

@Getter
@AllArgsConstructor
public class RepositoryResponse {
    private Long id;
    private String githubRepoFullName;
    private Instant createdAt;
}
