package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    @JsonProperty("token")
    private String token;

    @JsonProperty("access_token")
    public String getAccessToken() {
        return token;
    }

    @JsonProperty("token_type")
    private String tokenType = "bearer";

    @JsonProperty("user")
    private UserResponse user;

    public AuthResponse(String token, UserResponse user) {
        this.token = token;
        this.user = user;
        this.tokenType = "bearer";
    }
}
