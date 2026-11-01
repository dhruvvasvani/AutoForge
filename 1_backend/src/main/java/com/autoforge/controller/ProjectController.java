package com.autoforge.controller;

import com.autoforge.dto.ProjectCreateRequest;
import com.autoforge.dto.ProjectDetailResponse;
import com.autoforge.dto.ProjectPolicyDto;
import com.autoforge.service.PolicyEngine;
import com.autoforge.service.ProjectService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/v1/projects")
@RequiredArgsConstructor
public class ProjectController {
    private final ProjectService projectService;
    private final PolicyEngine policyEngine;

    @PostMapping
    public ResponseEntity<ProjectDetailResponse> createProject(
            @Valid @RequestBody ProjectCreateRequest request,
            Principal principal
    ) {
        String email = principal != null ? principal.getName() : null;
        ProjectDetailResponse response = projectService.createProject(request, email);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    public ResponseEntity<List<ProjectDetailResponse>> listProjects(
            @RequestParam(name = "skip", defaultValue = "0") int skip,
            @RequestParam(name = "limit", defaultValue = "10") int limit,
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            Principal principal
    ) {
        if (page != null && size != null) {
            skip = page * size;
            limit = size;
        }
        String email = principal != null ? principal.getName() : null;
        return ResponseEntity.ok(projectService.listProjects(skip, limit, email));
    }

    @GetMapping("/{projectId}")
    public ResponseEntity<ProjectDetailResponse> getProject(
            @PathVariable("projectId") Long projectId,
            Principal principal
    ) {
        String email = principal != null ? principal.getName() : null;
        return ResponseEntity.ok(projectService.getProject(projectId, email));
    }

    @GetMapping("/{projectId}/policy")
    public ResponseEntity<ProjectPolicyDto> getProjectPolicy(@PathVariable("projectId") Long projectId) {
        return ResponseEntity.ok(policyEngine.getProjectPolicy(projectId));
    }

    @PutMapping("/{projectId}/policy")
    public ResponseEntity<ProjectPolicyDto> updateProjectPolicy(
            @PathVariable("projectId") Long projectId,
            @RequestBody ProjectPolicyDto dto
    ) {
        return ResponseEntity.ok(policyEngine.updateProjectPolicy(projectId, dto));
    }
}
