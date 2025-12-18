package com.keycloak.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpSendRequest {

    @NotBlank(message = "Username is required")
    private String username;

    @JsonProperty("phone_number")
    private String phoneNumber;

    private String email;

    /**
     * OTP delivery channel: SMS, EMAIL, or BOTH
     */
    @Builder.Default
    private OtpChannel channel = OtpChannel.SMS;

    public enum OtpChannel {
        SMS,
        EMAIL,
        BOTH
    }
}
