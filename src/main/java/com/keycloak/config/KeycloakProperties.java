package com.keycloak.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "app.idp.keycloak")
public class KeycloakProperties {

    private String serverUrl;
    private String realm;
    private String clientId;
    private String clientSecret;
    private String adminClientId;
    private String adminClientSecret;
    private String grantType = "password";

    // Admin credentials for Keycloak Admin API
    private Admin admin = new Admin();

    @Getter
    @Setter
    public static class Admin {
        private String username;
        private String password;
    }
}
