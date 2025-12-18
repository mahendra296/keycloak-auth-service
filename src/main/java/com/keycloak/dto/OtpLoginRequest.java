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
public class OtpLoginRequest {

    private String username;

    @FormProperty("client_id")
    private String clientId;

    @FormProperty("client_secret")
    private String clientSecret;

    private String scope;

    @FormProperty("grant_type")
    private String grantType;

    @FormProperty("auth_type")
    private String authType = "password";
}
