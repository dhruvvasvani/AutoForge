package com.autoforge.service;

import com.autoforge.dto.*;
import com.autoforge.entity.Plan;
import com.autoforge.entity.User;
import com.autoforge.exception.ApiException;
import com.autoforge.repository.PlanRepository;
import com.autoforge.repository.UserRepository;
import com.autoforge.security.AppUserDetailsService;
import com.autoforge.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {
    private final UserRepository userRepository;
    private final PlanRepository planRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final AppUserDetailsService userDetailsService;
    private final AuditLogService auditLogService;

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ApiException(HttpStatus.CONFLICT, "An account with this email already exists");
        }
        Plan freePlan = planRepository.findByName("FREE").orElse(null);
        User user = new User();
        user.setFullName(request.getEffectiveFullName());
        user.setEmail(request.getEmail());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setRole(com.autoforge.entity.Role.DEVELOPER);
        user.setPlan(freePlan);
        userRepository.save(user);
        auditLogService.log(user, "REGISTER", "New user registered: " + user.getEmail());
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());
        return new AuthResponse(jwtService.generateToken(userDetails), toUserResponse(user));
    }

    public AuthResponse login(LoginRequest request) {
        String email = request.getEffectiveEmail();
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, request.getPassword()));
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Invalid email or password"));
        auditLogService.log(user, "LOGIN", "User logged in");
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());
        return new AuthResponse(jwtService.generateToken(userDetails), toUserResponse(user));
    }

    public UserResponse getCurrentUser(String email) {
        return toUserResponse(userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found")));
    }

    public UserResponse updateProfile(String currentEmail, UpdateProfileRequest request) {
        User user = userRepository.findByEmail(currentEmail)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        String newEmail = request.getEmail().trim();
        if (!newEmail.equalsIgnoreCase(user.getEmail()) && userRepository.existsByEmail(newEmail)) {
            throw new ApiException(HttpStatus.CONFLICT, "An account with this email already exists");
        }
        List<String> updatedFields = new ArrayList<>();
        if (!request.getFullName().trim().equals(user.getFullName())) {
            user.setFullName(request.getFullName().trim());
            updatedFields.add("fullName");
        }
        if (!newEmail.equalsIgnoreCase(user.getEmail())) {
            user.setEmail(newEmail);
            updatedFields.add("email");
        }
        user.setUpdatedAt(Instant.now());
        User savedUser = userRepository.save(user);
        String details = updatedFields.isEmpty() ? "No fields changed" : "Updated profile fields: " + String.join(", ", updatedFields);
        auditLogService.log(savedUser, "PROFILE_UPDATE", details);
        return toUserResponse(savedUser);
    }

    public void changePassword(String email, ChangePasswordRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Current password is incorrect");
        }
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setUpdatedAt(Instant.now());
        auditLogService.log(userRepository.save(user), "PASSWORD_CHANGE", "Password changed");
    }

    private UserResponse toUserResponse(User user) {
        return new UserResponse(user.getId(), user.getFullName(), user.getEmail(),
                user.getRole().name(), user.getStatus().name(),
                user.getPlan() != null ? user.getPlan().getName() : null);
    }
}
