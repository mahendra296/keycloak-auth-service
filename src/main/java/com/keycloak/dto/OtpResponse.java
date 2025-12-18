package com.keycloak.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpResponse {

    private boolean success;

    private String message;

    @JsonProperty("expires_in_seconds")
    private int expiresInSeconds;

    /**
     * Only included in development/test environment
     */
    @JsonProperty("otp_code")
    private String otpCode;

    @JsonProperty("session_id")
    private String sessionId;

    public static OtpResponse success(String message, int expiresInSeconds) {
        return OtpResponse.builder()
                .success(true)
                .message(message)
                .expiresInSeconds(expiresInSeconds)
                .build();
    }

    public static OtpResponse successWithOtp(String message, int expiresInSeconds, String otpCode) {
        return OtpResponse.builder()
                .success(true)
                .message(message)
                .expiresInSeconds(expiresInSeconds)
                .otpCode(otpCode)
                .build();
    }

    public static OtpResponse failure(String message) {
        return OtpResponse.builder().success(false).message(message).build();
    }
}
