package com.autoforge.repository;

import com.autoforge.entity.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {
    List<Scan> findByRepositoryId(Long repositoryId);
}
