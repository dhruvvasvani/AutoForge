package com.autoforge.service;

import com.autoforge.dto.ScanSourceImportRequest;
import com.autoforge.dto.ScanSourceUploadResponse;
import com.autoforge.entity.Project;
import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import com.autoforge.entity.User;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.ProjectRepository;
import com.autoforge.repository.ScanRepository;
import com.autoforge.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Path;

@Service
@RequiredArgsConstructor
public class ScanSourceService {
    private final ScanSourceStorageService storageService;
    private final ProjectRepository projectRepository;
    private final ScanRepository scanRepository;
    private final UserRepository userRepository;

    @Transactional
    public ScanSourceUploadResponse uploadZip(MultipartFile archive, String projectName, String branch, String userEmail) throws IOException {
        requireProjectName(projectName);
        Path sourceDirectory = storageService.storeZip(archive);
        return createScan(projectName, branch, null, sourceDirectory, userEmail);
    }

    @Transactional
    public ScanSourceUploadResponse importDirectory(ScanSourceImportRequest request, String userEmail) throws IOException {
        requireProjectName(request.getProjectName());
        Path sourceDirectory = storageService.validateSourceDirectory(request.getSourcePath());
        return createScan(request.getProjectName(), request.getBranch(), request.getCommitSha(), sourceDirectory, userEmail);
    }

    private void requireProjectName(String projectName) {
        if (projectName == null || projectName.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Project name is required.");
        }
    }

    private ScanSourceUploadResponse createScan(String projectName, String branch, String commitSha, Path sourceDirectory, String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Authenticated user was not found."));
        Project project = new Project();
        project.setName(projectName);
        project.setRepoUrl(sourceDirectory.toUri().toString());
        project.setDefaultBranch(branch == null || branch.isBlank() ? "main" : branch);
        project.setUser(user);
        Project savedProject = projectRepository.save(project);

        Scan scan = new Scan();
        scan.setProject(savedProject);
        scan.setCommitSha(commitSha);
        scan.setBranch(savedProject.getDefaultBranch());
        scan.setSourcePath(sourceDirectory.toString());
        scan.setStatus(ScanStatus.QUEUED);
        Scan savedScan = scanRepository.save(scan);

        return ScanSourceUploadResponse.builder()
                .scanId(savedScan.getId())
                .projectId(savedProject.getId())
                .status(savedScan.getStatus().name())
                .sourceDirectory(storageService.displayPath(sourceDirectory))
                .build();
    }
}
