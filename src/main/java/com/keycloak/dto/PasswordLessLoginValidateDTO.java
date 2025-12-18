package com.keycloak.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordLessLoginValidateDTO {

    private String phoneNumber;

    private String sessionCode;

    private String otp;

    private Boolean isBiometricEnabled = false;
}
