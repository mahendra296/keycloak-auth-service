package com.keycloak.controller;

import com.keycloak.dto.*;
import com.keycloak.service.AuthService;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Login with username and password
     * POST /api/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login request received for username: {}", request.getUsername());

        AuthResponse authResponse = authService.loginWithPassword(request);

        return ResponseEntity.ok(ApiResponse.success(authResponse, "Login successful"));
    }

    /**
     * Verify OTP and login
     * POST /api/auth/otp/verify
     */
    @PostMapping("/otp/verify")
    public ResponseEntity<ApiResponse<AuthResponse>> verifyOtp(@Valid @RequestBody OtpVerificationRequest request) {
        log.info("OTP verification request received for username: {}", request.getUsername());

        AuthResponse authResponse = authService.loginWithOtp(request);

        return ResponseEntity.ok(ApiResponse.success(authResponse, "OTP verification successful"));
    }

    /**
     * Refresh access token
     * POST /api/auth/refresh
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(@RequestParam("refresh_token") String refreshToken) {
        log.info("Token refresh request received");

        AuthResponse authResponse = authService.refreshToken(refreshToken);

        return ResponseEntity.ok(ApiResponse.success(authResponse, "Token refreshed successfully"));
    }

    /**
     * Logout user
     * POST /api/auth/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestParam("refresh_token") String refreshToken) {
        log.info("Logout request received");

        authService.logout(refreshToken);

        return ResponseEntity.ok(ApiResponse.success(null, "Logout successful"));
    }

    /**
     * Get user information
     * GET /api/auth/userinfo
     */
    @GetMapping("/userinfo")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUserInfo(
            @RequestHeader("Authorization") String authorization) {
        log.info("User info request received");

        Map<String, Object> userInfo = authService.getUserInfo(authorization);

        return ResponseEntity.ok(ApiResponse.success(userInfo, "User information retrieved"));
    }

    /*
     Login with PIN
     POST /api/auth/login/pin
    */
    @PostMapping("/login/pin")
    public ResponseEntity<ApiResponse<AuthResponse>> loginWithPin(
            @RequestParam String username, @RequestParam String pin) {
        log.info("PIN login request received for username: {}", username);

        AuthResponse authResponse = authService.loginWithPin(username, pin);

        return ResponseEntity.ok(ApiResponse.success(authResponse, "PIN login successful"));
    }

    /**
     * Initiate passwordless login (send OTP)
     * POST /api/auth/passwordless/initiate
     */
    @PostMapping("/passwordless/initiate")
    public ResponseEntity<ApiResponse<PasswordLessLoginInitiateResDTO>> initiatePasswordlessLogin(
            @RequestParam String username) {
        log.info("Passwordless login initiation request received for username: {}", username);

        PasswordLessLoginInitiateResDTO response = authService.initiatePasswordlessLogin(username);

        return ResponseEntity.ok(ApiResponse.success(response, "OTP sent successfully"));
    }

    /**
     * Validate passwordless login (verify OTP)
     * POST /api/auth/passwordless/validate
     */
    @PostMapping("/passwordless/validate")
    public ResponseEntity<ApiResponse<AuthResponse>> validatePasswordlessLogin(
            @Valid @RequestBody PasswordLessLoginValidateDTO request) {
        log.info("Passwordless login validation request received for phone: {}", request.getPhoneNumber());

        AuthResponse authResponse;
        if (Boolean.TRUE.equals(request.getIsBiometricEnabled())) {
            authResponse = authService.validateBiometricPasswordlessLogin(
                    request.getPhoneNumber(), request.getSessionCode(), request.getOtp());
        } else {
            authResponse = authService.validatePasswordlessLogin(
                    request.getPhoneNumber(), request.getSessionCode(), request.getOtp());
        }

        return ResponseEntity.ok(ApiResponse.success(authResponse, "Passwordless login successful"));
    }

    /**
     * Validate token (check if active)
     * GET /api/auth/validate
     */
    @GetMapping("/validate")
    public ResponseEntity<ApiResponse<Boolean>> validateToken(@RequestHeader("Authorization") String authorization) {
        log.info("Token validation request received");

        String token = authorization.startsWith("Bearer ") ? authorization.substring(7) : authorization;
        boolean isActive = authService.isTokenActive(token);

        return ResponseEntity.ok(
                ApiResponse.success(isActive, isActive ? "Token is valid" : "Token is invalid or expired"));
    }

    // ==================== OTP ENDPOINTS ====================

    /**
     * Send OTP to user
     * POST /api/auth/otp/send
     */
    @PostMapping("/otp/send")
    public ResponseEntity<ApiResponse<OtpResponse>> sendOtp(@Valid @RequestBody OtpSendRequest request) {
        log.info("OTP send request received for username: {}", request.getUsername());

        OtpResponse response = authService.sendOtp(request);

        return ResponseEntity.ok(ApiResponse.success(response, response.getMessage()));
    }

    /**
     * Send OTP to user (simple endpoint with just username)
     * POST /api/auth/otp/send/{username}
     */
    @PostMapping("/otp/send/{username}")
    public ResponseEntity<ApiResponse<OtpResponse>> sendOtpSimple(@PathVariable String username) {
        log.info("OTP send request received for username: {}", username);

        OtpResponse response = authService.sendOtp(username);

        return ResponseEntity.ok(ApiResponse.success(response, response.getMessage()));
    }

    /**
     * Validate OTP
     * POST /api/auth/otp/validate
     */
    @PostMapping("/otp/validate")
    public ResponseEntity<ApiResponse<OtpResponse>> validateOtp(@Valid @RequestBody OtpVerificationRequest request) {
        log.info("OTP validation request received for username: {}", request.getUsername());

        OtpResponse response = authService.validateOtp(request.getUsername(), request.getOtpCode());

        return ResponseEntity.ok(ApiResponse.success(response, response.getMessage()));
    }

    /**
     * Validate OTP and login (get tokens)
     * POST /api/auth/otp/validate-and-login
     */
    @PostMapping("/otp/validate-and-login")
    public ResponseEntity<ApiResponse<AuthResponse>> validateOtpAndLogin(
            @Valid @RequestBody OtpVerificationRequest request) {
        log.info("OTP validate and login request received for username: {}", request.getUsername());

        AuthResponse authResponse = authService.validateOtpAndLogin(request);

        return ResponseEntity.ok(ApiResponse.success(authResponse, "OTP validated and login successful"));
    }

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> health() {
        return ResponseEntity.ok(ApiResponse.success("Service is running", "Health check passed"));
    }
}
