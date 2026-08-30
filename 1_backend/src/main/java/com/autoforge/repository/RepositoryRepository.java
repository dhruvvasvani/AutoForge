package com.autoforge.repository;

import com.autoforge.entity.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RepositoryRepository extends JpaRepository<Repository, Long> {
    List<Repository> findByUserId(Long userId);
    Optional<Repository> findByGithubRepoFullName(String githubRepoFullName);
}
