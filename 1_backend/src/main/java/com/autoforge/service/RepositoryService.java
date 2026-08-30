package com.autoforge.service;

// Week 9 deliverable: Repository APIs + GitHub integration groundwork.
// Registers a repo against the current user; webhook auto-registration with
// GitHub's REST API is the next seam (left as TODO - needs a GitHub OAuth
// App / PAT, intentionally not hardcoded here).
import com.autoforge.dto.RepositoryResponse;
import com.autoforge.entity.Repository;
import com.autoforge.entity.User;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.RepositoryRepository;
import com.autoforge.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RepositoryService {

    private final RepositoryRepository repositoryRepository;
    private final UserRepository userRepository;

    public RepositoryResponse connectRepository(String userEmail, String githubRepoFullName) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));

        if (repositoryRepository.findByGithubRepoFullName(githubRepoFullName).isPresent()) {
            throw new ApiException(HttpStatus.CONFLICT, "Repository is already connected");
        }

        int currentCount = repositoryRepository.findByUserId(user.getId()).size();
        int maxAllowed = user.getPlan() != null ? user.getPlan().getMaxRepositories() : 1;
        if (currentCount >= maxAllowed) {
            throw new ApiException(HttpStatus.FORBIDDEN,
                    "Repository limit reached for your plan (" + maxAllowed + "). Request a plan upgrade.");
        }

        Repository repository = new Repository();
        repository.setUser(user);
        repository.setGithubRepoFullName(githubRepoFullName);
        // TODO(Week 10): call GitHub REST API to create the actual push webhook
        // and store the returned webhook_id here.

        return toResponse(repositoryRepository.save(repository));
    }

    public List<RepositoryResponse> listRepositories(String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        return repositoryRepository.findByUserId(user.getId()).stream().map(this::toResponse).toList();
    }

    public void deleteRepository(String userEmail, Long repositoryId) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        Repository repository = repositoryRepository.findById(repositoryId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Repository not found"));

        if (!repository.getUser().getId().equals(user.getId())) {
            throw new ApiException(HttpStatus.FORBIDDEN, "You do not own this repository");
        }

        repositoryRepository.delete(repository);
    }

    private RepositoryResponse toResponse(Repository repository) {
        return new RepositoryResponse(repository.getId(), repository.getGithubRepoFullName(), repository.getCreatedAt());
    }
}
