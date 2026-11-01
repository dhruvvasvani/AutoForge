package com.autoforge.service;

import com.autoforge.dto.ProjectCreateRequest;
import com.autoforge.dto.ProjectDetailResponse;
import com.autoforge.entity.Project;
import com.autoforge.entity.User;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.ProjectRepository;
import com.autoforge.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class ProjectService {
    private final ProjectRepository projectRepository;
    private final UserRepository userRepository;

    public ProjectDetailResponse createProject(ProjectCreateRequest request, String userEmail) {
        User user = null;
        if (userEmail != null) {
            user = userRepository.findByEmail(userEmail).orElse(null);
        }

        Project project = new Project();
        project.setName(request.getName());
        project.setRepoUrl(request.getRepoUrl());
        project.setDefaultBranch(request.getDefaultBranch() != null ? request.getDefaultBranch() : "main");
        project.setUser(user);

        Project saved = projectRepository.save(project);
        return toDetailResponse(saved);
    }

    public List<ProjectDetailResponse> listProjects(int skip, int limit, String userEmail) {
        int pageNumber = skip / (limit > 0 ? limit : 10);
        int pageSize = limit > 0 ? limit : 10;
        PageRequest pageRequest = PageRequest.of(pageNumber, pageSize, Sort.by(Sort.Direction.DESC, "createdAt"));

        return projectRepository.findAll(pageRequest)
                .stream()
                .map(this::toDetailResponse)
                .toList();
    }

    public ProjectDetailResponse getProject(Long projectId, String userEmail) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Project not found: " + projectId));
        return toDetailResponse(project);
    }

    public Project findEntityById(Long projectId) {
        return projectRepository.findById(projectId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Project not found: " + projectId));
    }

    private ProjectDetailResponse toDetailResponse(Project project) {
        return ProjectDetailResponse.builder()
                .id(project.getId())
                .name(project.getName())
                .repoUrl(project.getRepoUrl())
                .defaultBranch(project.getDefaultBranch())
                .createdAt(project.getCreatedAt())
                .build();
    }
}
