package com.autoforge.repository;

import com.autoforge.entity.CallTrace;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CallTraceRepository extends JpaRepository<CallTrace, Long> {
    List<CallTrace> findByFindingIdOrderByStepNumberAsc(Long findingId);
}
