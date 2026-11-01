package com.autoforge;

import com.autoforge.controller.AuthController;
import com.autoforge.dto.AuthResponse;
import com.autoforge.dto.LoginRequest;
import com.autoforge.dto.RegisterRequest;
import com.autoforge.dto.UserResponse;
import com.autoforge.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;

    private MockMvc mockMvc;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        AuthController authController = new AuthController(authService);
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
    }

    @Test
    void registerReturnsTokenForNewUser() throws Exception {
        RegisterRequest request = new RegisterRequest();
        request.setFullName("Test User");
        request.setEmail("test.user@example.com");
        request.setPassword("password123");

        UserResponse user = new UserResponse(1L, "Test User", "test.user@example.com", "DEVELOPER", "ACTIVE", "FREE");
        AuthResponse authResponse = new AuthResponse("mock-jwt-token-xyz", user);
        when(authService.register(any(RegisterRequest.class))).thenReturn(authResponse);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.access_token").value("mock-jwt-token-xyz"))
                .andExpect(jsonPath("$.token_type").value("bearer"));
    }

    @Test
    void loginReturnsTokenOnValidCredentials() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setEmail("test.user@example.com");
        request.setPassword("password123");

        UserResponse user = new UserResponse(1L, "Test User", "test.user@example.com", "DEVELOPER", "ACTIVE", "FREE");
        AuthResponse authResponse = new AuthResponse("mock-login-token-123", user);
        when(authService.login(any(LoginRequest.class))).thenReturn(authResponse);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("mock-login-token-123"));
    }

    @Test
    void getCurrentUserReturnsProfile() throws Exception {
        UserResponse userResponse = new UserResponse(1L, "Alice Developer", "alice@example.com", "DEVELOPER", "ACTIVE", "FREE");
        when(authService.getCurrentUser("alice@example.com")).thenReturn(userResponse);

        mockMvc.perform(get("/api/v1/auth/me")
                        .principal(() -> "alice@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alice@example.com"))
                .andExpect(jsonPath("$.role").value("DEVELOPER"));
    }
}
