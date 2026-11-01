package com.autoforge.repository;

import com.autoforge.entity.Scan;
import com.autoforge.entity.ScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Collection;

@Repository
public interface ScanRepository extends JpaRepository<Scan, Long> {
    List<Scan> findByRepositoryId(Long repositoryId);
    Page<Scan> findByProjectId(Long projectId, Pageable pageable);
    List<Scan> findByProjectId(Long projectId);

    @Query("""
            select distinct s from Scan s
            left join s.project p
            left join s.repository r
            where p.user.email = :email or r.user.email = :email
            """)
    Page<Scan> findVisibleToUser(@Param("email") String email, Pageable pageable);

    @Query("""
            select distinct s from Scan s
            left join s.project p
            left join s.repository r
            where s.id = :scanId and (p.user.email = :email or r.user.email = :email)
            """)
    Optional<Scan> findVisibleScanById(@Param("scanId") Long scanId, @Param("email") String email);

    @Modifying
    @Query("update Scan s set s.status = com.autoforge.entity.ScanStatus.RUNNING, s.startedAt = :startedAt, s.progress = 1 where s.id = :scanId and s.status = com.autoforge.entity.ScanStatus.QUEUED")
    int claimQueuedScan(@Param("scanId") Long scanId, @Param("startedAt") Instant startedAt);

    @Modifying
    @Query("""
            update Scan s set s.status = com.autoforge.entity.ScanStatus.QUEUED,
                s.startedAt = null, s.completedAt = null, s.errorMessage = :message, s.progress = 0
            where s.id = :scanId
                and s.status in (com.autoforge.entity.ScanStatus.RUNNING, com.autoforge.entity.ScanStatus.PROCESSING)
                and s.startedAt < :staleBefore
            """)
    int requeueStaleScan(@Param("scanId") Long scanId, @Param("staleBefore") Instant staleBefore,
                         @Param("message") String message);

    List<Scan> findTop100ByStatusInAndStartedAtBeforeOrderByStartedAtAsc(
            Collection<ScanStatus> statuses, Instant startedAt);

    @Modifying
    @Query("""
            update Scan s set s.status = com.autoforge.entity.ScanStatus.FAILED,
                s.errorMessage = :errorMessage, s.completedAt = :completedAt
            where s.id = :scanId and s.status = com.autoforge.entity.ScanStatus.QUEUED
            """)
    int failQueuedScan(@Param("scanId") Long scanId, @Param("errorMessage") String errorMessage,
                       @Param("completedAt") Instant completedAt);

    Optional<Scan> findByIdempotencyKey(String idempotencyKey);
    Optional<Scan> findFirstByRepositoryIdAndCommitSha(Long repositoryId, String commitSha);
}
