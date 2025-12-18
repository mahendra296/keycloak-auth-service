package com.keycloak.dto;

public class OtpValidateRequest {

    private String otp;

    public OtpValidateRequest() {}

    public OtpValidateRequest(String otp) {
        this.otp = otp;
    }

    public String getOtp() {
        return otp;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }
}
