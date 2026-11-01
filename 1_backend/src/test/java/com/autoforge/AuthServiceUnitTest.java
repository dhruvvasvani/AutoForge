package com.autoforge;

import com.autoforge.dto.ChangePasswordRequest;
import com.autoforge.dto.RegisterRequest;
import com.autoforge.dto.UpdateProfileRequest;
import com.autoforge.dto.UserResponse;
import com.autoforge.entity.Plan;
import com.autoforge.entity.Role;
import com.autoforge.entity.User;
import com.autoforge.entity.UserStatus;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.PlanRepository;
import com.autoforge.repository.UserRepository;
import com.autoforge.security.AppUserDetailsService;
import com.autoforge.security.JwtService;
import com.autoforge.service.AuditLogService;
import com.autoforge.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import org.springframework.security.core.userdetails.UserDetails;

@ExtendWith(MockitoExtension.class)
class AuthServiceUnitTest {
    @Mock
    private UserRepository userRepository;
    @Mock
    private PlanRepository planRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private AppUserDetailsService userDetailsService;
    @Mock
    private AuditLogService auditLogService;

    @InjectMocks
    private AuthService authService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        Plan plan = new Plan();
        plan.setName("FREE");

        sampleUser = new User();
        sampleUser.setId(1L);
        sampleUser.setFullName("Original Name");
        sampleUser.setEmail("original@example.com");
        sampleUser.setPasswordHash("hashed_old_password");
        sampleUser.setRole(Role.USER);
        sampleUser.setStatus(UserStatus.ACTIVE);
        sampleUser.setPlan(plan);
    }

    @Test
    void updateProfile_Success() {
        when(userRepository.findByEmail("original@example.com")).thenReturn(Optional.of(sampleUser));
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UpdateProfileRequest request = new UpdateProfileRequest("New Name", "new@example.com");
        UserResponse response = authService.updateProfile("original@example.com", request);

        assertEquals("New Name", response.getFullName());
        assertEquals("new@example.com", response.getEmail());
        verify(auditLogService).log(eq(sampleUser), eq("PROFILE_UPDATE"), contains("Updated profile fields"));
    }

    @Test
    void registrationIgnoresClientSuppliedAdminRole() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("new@example.com");
        request.setPassword("secret1");
        request.setRole("ADMIN");
        when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(request.getPassword())).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(userDetailsService.loadUserByUsername(request.getEmail()))
                .thenReturn(org.springframework.security.core.userdetails.User
                        .withUsername(request.getEmail()).password("hashed").roles("DEVELOPER").build());
        when(jwtService.generateToken(any(UserDetails.class))).thenReturn("token");

        authService.register(request);

        org.mockito.ArgumentCaptor<User> captor = org.mockito.ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertEquals(Role.DEVELOPER, captor.getValue().getRole());
    }

    @Test
    void updateProfile_EmailAlreadyExists_ThrowsConflict() {
        when(userRepository.findByEmail("original@example.com")).thenReturn(Optional.of(sampleUser));
        when(userRepository.existsByEmail("taken@example.com")).thenReturn(true);

        UpdateProfileRequest request = new UpdateProfileRequest("New Name", "taken@example.com");
        ApiException ex = assertThrows(ApiException.class, () ->
                authService.updateProfile("original@example.com", request));

        assertEquals(HttpStatus.CONFLICT, ex.getStatus());
        verify(auditLogService, never()).log(any(), any(), any());
    }

    @Test
    void changePassword_Success() {
        when(userRepository.findByEmail("original@example.com")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("correctPassword", "hashed_old_password")).thenReturn(true);
        when(passwordEncoder.encode("newPassword123")).thenReturn("hashed_new_password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        ChangePasswordRequest request = new ChangePasswordRequest("correctPassword", "newPassword123");
        authService.changePassword("original@example.com", request);

        assertEquals("hashed_new_password", sampleUser.getPasswordHash());
        verify(auditLogService).log(eq(sampleUser), eq("PASSWORD_CHANGE"), eq("Password changed"));
    }

    @Test
    void changePassword_WrongPassword_ThrowsBadRequest() {
        when(userRepository.findByEmail("original@example.com")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("wrongPassword", "hashed_old_password")).thenReturn(false);

        ChangePasswordRequest request = new ChangePasswordRequest("wrongPassword", "newPassword123");
        ApiException ex = assertThrows(ApiException.class, () ->
                authService.changePassword("original@example.com", request));

        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatus());
        assertEquals("Current password is incorrect", ex.getMessage());
        verify(auditLogService, never()).log(any(), any(), any());
    }
}
