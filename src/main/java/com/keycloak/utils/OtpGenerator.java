package com.keycloak.utils;

import java.security.SecureRandom;
import org.springframework.stereotype.Component;

@Component
public class OtpGenerator {

    private static final String NUMBERS = "0123456789";
    private static final SecureRandom random = new SecureRandom();

    public String generateOtp(int length) {
        StringBuilder otp = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            otp.append(NUMBERS.charAt(random.nextInt(NUMBERS.length())));
        }
        return otp.toString();
    }

    public String generateNumericOtp(int length) {
        int min = (int) Math.pow(10, length - 1);
        int max = (int) Math.pow(10, length) - 1;
        return String.valueOf(random.nextInt(max - min + 1) + min);
    }
}
