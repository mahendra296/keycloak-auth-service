package com.keycloak.dto;

import feign.form.FormProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    private String username;
    private String password;

    @FormProperty("client_id")
    private String clientId;

    @FormProperty("client_secret")
    private String clientSecret;

    private String scope;

    @FormProperty("grant_type")
    private String grantType;

    @FormProperty("auth_type")
    private String authType = "password";

    private String pin;
    private String otp;

    public LoginRequest(
            String username, String password, String clientId, String clientSecret, String scope, String grantType) {
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scope = scope;
        this.grantType = grantType;
    }

    public LoginRequest(
            String username,
            String password,
            String clientId,
            String clientSecret,
            String scope,
            String grantType,
            String authType,
            String pin) {
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scope = scope;
        this.grantType = grantType;
        this.authType = authType;
        this.pin = pin;
    }
}
