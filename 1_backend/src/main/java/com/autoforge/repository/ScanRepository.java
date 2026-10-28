package com.autoforge.repository;

import com.autoforge.entity.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ScanRepository extends JpaRepository<Scan, Long> {
    List<Scan> findByRepositoryId(Long repositoryId);
    List<Scan> findTop20ByRepositoryIdOrderByCreatedAtDesc(Long repositoryId);
    Optional<Scan> findByIdAndRepositoryUserEmail(Long id, String email);
}
