package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterRequest {
    @JsonProperty("full_name")
    private String fullName;

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    @JsonProperty("email")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters")
    @JsonProperty("password")
    private String password;

    @JsonProperty("role")
    private String role;

    public String getEffectiveFullName() {
        if (fullName != null && !fullName.isBlank()) {
            return fullName;
        }
        if (email != null && email.contains("@")) {
            return email.substring(0, email.indexOf("@"));
        }
        return "AutoForge User";
    }
}
