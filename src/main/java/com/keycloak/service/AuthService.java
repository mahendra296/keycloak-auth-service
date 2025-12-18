package com.keycloak.service;

import com.keycloak.client.KeycloakIdentityClient;
import com.keycloak.config.KeycloakProperties;
import com.keycloak.dto.*;
import com.keycloak.exceptions.AuthenticationException;
import com.keycloak.exceptions.OtpException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Authentication service that handles all authentication operations.
 * Uses KeycloakIdentityClient for Keycloak-specific operations.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(value = "app.idp.provider", havingValue = "keycloak", matchIfMissing = false)
public class AuthService {

    private final KeycloakIdentityClient keycloakIdentityClient;
    private final KeycloakProperties keycloakProperties;
    private final OtpService otpService;

    @Value("${otp.expiry-minutes:5}")
    private int otpExpiryMinutes;

    @Value("${app.otp.include-in-response:true}")
    private boolean includeOtpInResponse;

    // ==================== PASSWORD LOGIN ====================

    /**
     * Login with username/email and password.
     *
     * @param request LoginRequest containing username and password
     * @return AuthResponse containing tokens
     * @throws AuthenticationException if authentication fails
     */
    public AuthResponse loginWithPassword(LoginRequest request) {
        log.info("Attempting password login for user: {}", request.getUsername());
        validateNotBlank(request.getUsername(), "Username is required");
        validateNotBlank(request.getPassword(), "Password is required");

        try {
            LoginResponse loginResponse =
                    keycloakIdentityClient.userLogin(request.getUsername(), request.getPassword());

            log.info("Password login successful for user: {}", request.getUsername());
            return mapToAuthResponse(loginResponse);
        } catch (Exception e) {
            log.error("Password login failed for user: {}", request.getUsername(), e);
            throw new AuthenticationException("Invalid username or password", e);
        }
    }

    // ==================== PIN LOGIN ====================

    /**
     * Login with PIN.
     *
     * @param username User's username or email
     * @param pin      User's login PIN
     * @return AuthResponse containing tokens
     * @throws AuthenticationException if authentication fails
     */
    public AuthResponse loginWithPin(String username, String pin) {
        log.info("Attempting PIN login for user: {}", username);
        validateNotBlank(username, "Username is required");
        validateNotBlank(pin, "PIN is required");

        try {
            LoginResponse loginResponse = keycloakIdentityClient.pinLogin(username, pin);
            log.info("PIN login successful for user: {}", username);
            return mapToAuthResponse(loginResponse);
        } catch (Exception e) {
            log.error("PIN login failed for user: {}", username, e);
            throw new AuthenticationException("Invalid PIN", e);
        }
    }

    // ==================== OTP / PASSWORDLESS LOGIN ====================

    /**
     * Login with OTP verification.
     *
     * @param request OtpVerificationRequest containing username and OTP code
     * @return AuthResponse containing tokens
     * @throws AuthenticationException if OTP verification fails
     */
    public AuthResponse loginWithOtp(OtpVerificationRequest request) {
        log.info("Attempting OTP login for user: {}", request.getUsername());
        validateNotBlank(request.getUsername(), "Username is required");
        validateNotBlank(request.getOtpCode(), "OTP code is required");

        try {
            PasswordLessLoginValidateDTO dto = PasswordLessLoginValidateDTO.builder()
                    .phoneNumber(request.getUsername())
                    .otp(request.getOtpCode())
                    .isBiometricEnabled(false)
                    .build();

            LoginResponse loginResponse = keycloakIdentityClient.passwordLessLoginValidate(dto);
            log.info("OTP login successful for user: {}", request.getUsername());
            return mapToAuthResponse(loginResponse);
        } catch (Exception e) {
            log.error("OTP login failed for user: {}", request.getUsername(), e);
            throw new AuthenticationException("Invalid OTP", e);
        }
    }

    /**
     * Initiate passwordless login by sending OTP.
     *
     * @param username User's username, email, or phone number
     * @return PasswordLessLoginInitiateResDTO containing session code
     * @throws AuthenticationException if initiation fails
     */
    public PasswordLessLoginInitiateResDTO initiatePasswordlessLogin(String username) {
        log.info("Initiating passwordless login for user: {}", username);
        validateNotBlank(username, "Username is required");

        try {
            PasswordLessLoginInitiateResDTO response = keycloakIdentityClient.passwordLessLogin(username);
            log.info("Passwordless login initiated for user: {}", username);
            return response;
        } catch (Exception e) {
            log.error("Passwordless login initiation failed for user: {}", username, e);
            throw new AuthenticationException("Failed to initiate passwordless login", e);
        }
    }

    /**
     * Validate passwordless login with OTP.
     *
     * @param phoneNumber User's phone number
     * @param sessionCode Session code from initiation
     * @param otp         OTP entered by user
     * @return AuthResponse containing tokens
     * @throws AuthenticationException if validation fails
     */
    public AuthResponse validatePasswordlessLogin(String phoneNumber, String sessionCode, String otp) {
        log.info("Validating passwordless login for user: {}", phoneNumber);
        validateNotBlank(phoneNumber, "Phone number is required");
        validateNotBlank(otp, "OTP is required");

        try {
            PasswordLessLoginValidateDTO dto = PasswordLessLoginValidateDTO.builder()
                    .phoneNumber(phoneNumber)
                    .sessionCode(sessionCode)
                    .otp(otp)
                    .isBiometricEnabled(false)
                    .build();

            LoginResponse loginResponse = keycloakIdentityClient.passwordLessLoginValidate(dto);
            log.info("Passwordless login validation successful for user: {}", phoneNumber);
            return mapToAuthResponse(loginResponse);
        } catch (Exception e) {
            log.error("Passwordless login validation failed for user: {}", phoneNumber, e);
            throw new AuthenticationException("Invalid OTP or session expired", e);
        }
    }

    /**
     * Validate biometric passwordless login with OTP (offline access).
     *
     * @param phoneNumber User's phone number
     * @param sessionCode Session code from initiation
     * @param otp         OTP entered by user
     * @return AuthResponse containing tokens with offline_access scope
     * @throws AuthenticationException if validation fails
     */
    public AuthResponse validateBiometricPasswordlessLogin(String phoneNumber, String sessionCode, String otp) {
        log.info("Validating biometric passwordless login for user: {}", phoneNumber);
        validateNotBlank(phoneNumber, "Phone number is required");
        validateNotBlank(otp, "OTP is required");

        try {
            PasswordLessLoginValidateDTO dto = PasswordLessLoginValidateDTO.builder()
                    .phoneNumber(phoneNumber)
                    .sessionCode(sessionCode)
                    .otp(otp)
                    .isBiometricEnabled(true)
                    .build();

            LoginResponse loginResponse = keycloakIdentityClient.biometricPasswordLessLoginValidate(dto);
            log.info("Biometric passwordless login validation successful for user: {}", phoneNumber);
            return mapToAuthResponse(loginResponse);
        } catch (Exception e) {
            log.error("Biometric passwordless login validation failed for user: {}", phoneNumber, e);
            throw new AuthenticationException("Invalid OTP or session expired", e);
        }
    }

    // ==================== TOKEN MANAGEMENT ====================

    /**
     * Refresh access token using refresh token.
     *
     * @param refreshToken Valid refresh token
     * @return AuthResponse containing new tokens
     * @throws AuthenticationException if refresh fails
     */
    public AuthResponse refreshToken(String refreshToken) {
        log.info("Refreshing access token");
        validateNotBlank(refreshToken, "Refresh token is required");

        try {
            LoginResponse loginResponse = keycloakIdentityClient.refreshToken(refreshToken, null);
            log.info("Token refresh successful");
            return mapToAuthResponse(loginResponse);
        } catch (Exception e) {
            log.error("Token refresh failed", e);
            throw new AuthenticationException("Invalid or expired refresh token", e);
        }
    }

    /**
     * Logout user by invalidating refresh token.
     *
     * @param refreshToken Refresh token to invalidate
     * @throws AuthenticationException if logout fails
     */
    public void logout(String refreshToken) {
        log.info("Logging out user");
        validateNotBlank(refreshToken, "Refresh token is required");

        Client client = ClientBuilder.newClient();
        try {
            String logoutUrl = keycloakProperties.getServerUrl() + "/realms/" + keycloakProperties.getRealm()
                    + "/protocol/openid-connect/logout";

            Form form = new Form()
                    .param("refresh_token", refreshToken)
                    .param("client_id", keycloakProperties.getClientId())
                    .param("client_secret", keycloakProperties.getClientSecret());

            Response response = client.target(logoutUrl).request().post(Entity.form(form));

            if (response.getStatus() == 204 || response.getStatus() == 200) {
                log.info("Logout successful");
            } else {
                log.error("Logout failed with status: {}", response.getStatus());
                throw new AuthenticationException("Logout failed");
            }
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Logout failed", e);
            throw new AuthenticationException("Logout failed", e);
        } finally {
            client.close();
        }
    }

    // ==================== USER INFO & TOKEN INTROSPECTION ====================

    /**
     * Get user information from access token.
     *
     * @param accessToken Valid access token (can include "Bearer " prefix)
     * @return Map containing user information
     * @throws AuthenticationException if fetching user info fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getUserInfo(String accessToken) {
        log.info("Fetching user information");
        validateNotBlank(accessToken, "Access token is required");

        Client client = ClientBuilder.newClient();
        try {
            String userInfoUrl = keycloakProperties.getServerUrl() + "/realms/" + keycloakProperties.getRealm()
                    + "/protocol/openid-connect/userinfo";

            String bearerToken = accessToken.startsWith("Bearer ") ? accessToken : "Bearer " + accessToken;

            Response response = client.target(userInfoUrl)
                    .request(MediaType.APPLICATION_JSON)
                    .header("Authorization", bearerToken)
                    .get();

            if (response.getStatus() == 200) {
                Map<String, Object> userInfo = response.readEntity(Map.class);
                log.info("User information retrieved successfully");
                return userInfo;
            } else {
                log.error("Failed to fetch user info with status: {}", response.getStatus());
                throw new AuthenticationException("Failed to fetch user information");
            }
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to fetch user information", e);
            throw new AuthenticationException("Failed to fetch user information", e);
        } finally {
            client.close();
        }
    }

    /**
     * Introspect token to check validity and get claims.
     *
     * @param token Token to introspect
     * @return Map containing token information including 'active' boolean
     * @throws AuthenticationException if introspection fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> introspectToken(String token) {
        log.info("Introspecting token");
        validateNotBlank(token, "Token is required");

        Client client = ClientBuilder.newClient();
        try {
            String introspectUrl = keycloakProperties.getServerUrl() + "/realms/" + keycloakProperties.getRealm()
                    + "/protocol/openid-connect/token/introspect";

            Form form = new Form()
                    .param("token", token)
                    .param("client_id", keycloakProperties.getClientId())
                    .param("client_secret", keycloakProperties.getClientSecret());

            Response response = client.target(introspectUrl)
                    .request(MediaType.APPLICATION_JSON)
                    .post(Entity.form(form));

            if (response.getStatus() == 200) {
                Map<String, Object> tokenInfo = response.readEntity(Map.class);
                log.info("Token introspection successful, active: {}", tokenInfo.get("active"));
                return tokenInfo;
            } else {
                log.error("Token introspection failed with status: {}", response.getStatus());
                throw new AuthenticationException("Token introspection failed");
            }
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Token introspection failed", e);
            throw new AuthenticationException("Token introspection failed", e);
        } finally {
            client.close();
        }
    }

    /**
     * Validate if a token is active.
     *
     * @param token Token to validate
     * @return true if token is active, false otherwise
     */
    public boolean isTokenActive(String token) {
        try {
            Map<String, Object> tokenInfo = introspectToken(token);
            Object active = tokenInfo.get("active");
            return active != null && Boolean.TRUE.equals(active);
        } catch (Exception e) {
            log.warn("Token validation failed", e);
            return false;
        }
    }

    // ==================== OTP MANAGEMENT ====================

    /**
     * Send OTP to user.
     *
     * @param request OtpSendRequest containing username and delivery preferences
     * @return OtpResponse with status and expiry information
     * @throws AuthenticationException if OTP generation fails
     */
    public OtpResponse sendOtp(OtpSendRequest request) {
        log.info("Sending OTP for user: {}", request.getUsername());
        validateNotBlank(request.getUsername(), "Username is required");

        try {
            // Generate OTP using OtpService
            String otpCode = otpService.generateOtp(request.getUsername());

            // In production, send OTP via SMS/Email based on channel
            // For now, we're logging and optionally returning it
            sendOtpToUser(request, otpCode);

            int expiresInSeconds = otpExpiryMinutes * 60;

            log.info("OTP sent successfully for user: {}", request.getUsername());

            // In development, include OTP in response; in production, don't
            if (includeOtpInResponse) {
                return OtpResponse.successWithOtp("OTP sent successfully", expiresInSeconds, otpCode);
            } else {
                return OtpResponse.success("OTP sent successfully", expiresInSeconds);
            }
        } catch (Exception e) {
            log.error("Failed to send OTP for user: {}", request.getUsername(), e);
            throw new AuthenticationException("Failed to send OTP", e);
        }
    }

    /**
     * Send OTP to user with just username.
     *
     * @param username User's username or identifier
     * @return OtpResponse with status and expiry information
     * @throws AuthenticationException if OTP generation fails
     */
    public OtpResponse sendOtp(String username) {
        OtpSendRequest request = OtpSendRequest.builder().username(username).build();
        return sendOtp(request);
    }

    /**
     * Validate OTP entered by user.
     *
     * @param username User's username
     * @param otpCode  OTP code to validate
     * @return OtpResponse with validation result
     * @throws OtpException if OTP is invalid or expired
     */
    public OtpResponse validateOtp(String username, String otpCode) {
        log.info("Validating OTP for user: {}", username);
        validateNotBlank(username, "Username is required");
        validateNotBlank(otpCode, "OTP code is required");

        try {
            boolean isValid = otpService.verifyOtp(username, otpCode);

            if (isValid) {
                log.info("OTP validated successfully for user: {}", username);
                return OtpResponse.builder()
                        .success(true)
                        .message("OTP validated successfully")
                        .build();
            } else {
                log.warn("OTP validation failed for user: {}", username);
                return OtpResponse.failure("Invalid OTP");
            }
        } catch (OtpException e) {
            log.error("OTP validation error for user: {}", username, e);
            throw e;
        } catch (Exception e) {
            log.error("OTP validation failed for user: {}", username, e);
            throw new AuthenticationException("OTP validation failed", e);
        }
    }

    /**
     * Validate OTP and return authentication tokens if valid.
     *
     * @param request OtpVerificationRequest containing username and OTP
     * @return AuthResponse with tokens if OTP is valid
     * @throws OtpException if OTP is invalid
     * @throws AuthenticationException if authentication fails
     */
    public AuthResponse validateOtpAndLogin(OtpVerificationRequest request) {
        log.info("Validating OTP and logging in user: {}", request.getUsername());

        // First validate the OTP
        validateOtp(request.getUsername(), request.getOtpCode());

        // If OTP is valid, proceed with passwordless login
        return loginWithOtp(request);
    }

    // ==================== HELPER METHODS ====================

    private void validateNotBlank(String value, String message) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Maps LoginResponse to AuthResponse.
     */
    private AuthResponse mapToAuthResponse(LoginResponse loginResponse) {
        return AuthResponse.builder()
                .accessToken(loginResponse.getAccessToken())
                .refreshToken(loginResponse.getRefreshToken())
                .expiresIn(loginResponse.getExpiresIn())
                .tokenType(loginResponse.getTokenType())
                .build();
    }

    /**
     * Send OTP to user via SMS/Email based on channel preference.
     * In production, this would integrate with SMS/Email providers.
     */
    private void sendOtpToUser(OtpSendRequest request, String otpCode) {
        OtpSendRequest.OtpChannel channel = request.getChannel();
        if (channel == null) {
            channel = OtpSendRequest.OtpChannel.SMS;
        }

        switch (channel) {
            case SMS:
                sendOtpViaSms(request.getPhoneNumber(), request.getUsername(), otpCode);
                break;
            case EMAIL:
                sendOtpViaEmail(request.getEmail(), request.getUsername(), otpCode);
                break;
            case BOTH:
                sendOtpViaSms(request.getPhoneNumber(), request.getUsername(), otpCode);
                sendOtpViaEmail(request.getEmail(), request.getUsername(), otpCode);
                break;
        }
    }

    /**
     * Send OTP via SMS.
     * TODO: Integrate with SMS provider (Twilio, AWS SNS, etc.)
     */
    private void sendOtpViaSms(String phoneNumber, String username, String otpCode) {
        if (StringUtils.hasText(phoneNumber)) {
            log.info("Sending OTP via SMS to {} for user {}", phoneNumber, username);
            // TODO: Implement SMS integration
            // smsService.sendOtp(phoneNumber, otpCode);
        } else {
            log.warn("No phone number provided for SMS OTP delivery for user: {}", username);
        }
    }

    /**
     * Send OTP via Email.
     * TODO: Integrate with Email service
     */
    private void sendOtpViaEmail(String email, String username, String otpCode) {
        if (StringUtils.hasText(email)) {
            log.info("Sending OTP via Email to {} for user {}", email, username);
            // TODO: Implement Email integration
            // emailService.sendOtp(email, otpCode);
        } else {
            log.warn("No email provided for Email OTP delivery for user: {}", username);
        }
    }
}
