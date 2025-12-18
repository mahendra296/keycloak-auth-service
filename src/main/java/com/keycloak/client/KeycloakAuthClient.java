package com.keycloak.client;

import com.keycloak.config.FeignFormEncoderConfig;
import com.keycloak.dto.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@ConditionalOnProperty(value = "app.idp.provider", havingValue = "keycloak", matchIfMissing = false)
@FeignClient(
        name = "keycloak-auth-client",
        url = "${app.idp.keycloak.serverUrl}",
        configuration = FeignFormEncoderConfig.class)
public interface KeycloakAuthClient {

    @PostMapping(
            value = "/realms/${app.idp.keycloak.realm}/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenResponse token(@RequestBody LoginRequest request);

    @PostMapping(
            value = "/realms/${app.idp.keycloak.realm}/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenResponse token(@RequestBody RefreshTokenRequest request);

    @PostMapping(
            value = "/realms/${app.idp.keycloak.realm}/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    OtpLoginResponse token(@RequestBody OtpLoginRequest request);

    @PostMapping(
            value =
                    "/realms/${app.idp.keycloak.realm}/login-actions/authenticate?code={sessionCode}&execution={executionId}",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenResponse action(@PathVariable String sessionCode, @PathVariable String executionId);
}
