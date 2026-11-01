package com.autoforge;

import com.autoforge.dto.FeedbackRequest;
import com.autoforge.entity.*;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.FeedbackLogRepository;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.FixRepository;
import com.autoforge.repository.UserRepository;
import com.autoforge.service.FeedbackService;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class FeedbackServiceTest {
    @Test
    void storesFeedbackForOwnedFindingAndAcceptsMatchingGeneratedPatch() {
        FeedbackLogRepository logs = mock(FeedbackLogRepository.class);
        FindingRepository findings = mock(FindingRepository.class);
        FixRepository fixes = mock(FixRepository.class);
        UserRepository users = mock(UserRepository.class);
        User user = new User();
        user.setId(3L);
        user.setEmail("owner@example.com");
        Finding finding = ownedFinding(user);
        finding.setId(17L);
        Fix fix = new Fix();
        fix.setId(29L);
        fix.setFinding(finding);
        fix.setStatus("GENERATED");
        when(users.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(findings.findById(17L)).thenReturn(Optional.of(finding));
        when(fixes.findById(29L)).thenReturn(Optional.of(fix));
        when(fixes.save(any(Fix.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(logs.save(any(FeedbackLog.class))).thenAnswer(invocation -> {
            FeedbackLog saved = invocation.getArgument(0);
            saved.setId(44L);
            return saved;
        });

        FeedbackRequest request = new FeedbackRequest();
        request.setFindingId(17L);
        request.setAction("ACCEPT_PATCH");
        request.setFixId(29L);
        request.setComment("Reviewed by developer");
        var response = new FeedbackService(logs, findings, fixes, users).submit(user.getEmail(), request);

        assertEquals(44L, response.getId());
        assertEquals("ACCEPT_PATCH", response.getAction());
        assertEquals("APPROVED", fix.getStatus());
        verify(logs).save(any(FeedbackLog.class));
        verify(fixes).save(fix);
    }

    @Test
    void rejectsFeedbackForFindingOwnedByAnotherUser() {
        FeedbackLogRepository logs = mock(FeedbackLogRepository.class);
        FindingRepository findings = mock(FindingRepository.class);
        FixRepository fixes = mock(FixRepository.class);
        UserRepository users = mock(UserRepository.class);
        User actor = new User();
        actor.setId(1L);
        actor.setEmail("actor@example.com");
        User owner = new User();
        owner.setId(2L);
        owner.setEmail("owner@example.com");
        Finding finding = ownedFinding(owner);
        finding.setId(18L);
        when(users.findByEmail(actor.getEmail())).thenReturn(Optional.of(actor));
        when(findings.findById(18L)).thenReturn(Optional.of(finding));
        FeedbackRequest request = new FeedbackRequest();
        request.setFindingId(18L);
        request.setAction("FALSE_POSITIVE");

        assertThrows(ApiException.class,
                () -> new FeedbackService(logs, findings, fixes, users).submit(actor.getEmail(), request));
        verifyNoInteractions(logs);
    }

    @Test
    void exportsOnlyFeedbackOwnedByAuthenticatedUser() {
        FeedbackLogRepository logs = mock(FeedbackLogRepository.class);
        FindingRepository findings = mock(FindingRepository.class);
        FixRepository fixes = mock(FixRepository.class);
        UserRepository users = mock(UserRepository.class);
        User owner = new User();
        owner.setId(5L);
        owner.setEmail("owner@example.com");
        Finding finding = new Finding();
        finding.setId(25L);
        FeedbackLog entry = new FeedbackLog();
        entry.setId(55L);
        entry.setFinding(finding);
        entry.setUser(owner);
        entry.setFeedbackAction("FALSE_POSITIVE");
        entry.setComment("Not exploitable");
        when(users.findByEmail(owner.getEmail())).thenReturn(Optional.of(owner));
        when(logs.findByUserIdOrderByCreatedAtAsc(owner.getId())).thenReturn(List.of(entry));

        var result = new FeedbackService(logs, findings, fixes, users).exportForUser(owner.getEmail());

        assertEquals(1, result.size());
        assertEquals(25L, result.get(0).getFindingId());
        assertEquals("FALSE_POSITIVE", result.get(0).getAction());
        verify(logs).findByUserIdOrderByCreatedAtAsc(5L);
    }

    private Finding ownedFinding(User owner) {
        Project project = new Project();
        project.setUser(owner);
        Scan scan = new Scan();
        scan.setProject(project);
        Finding finding = new Finding();
        finding.setScan(scan);
        return finding;
    }
}
