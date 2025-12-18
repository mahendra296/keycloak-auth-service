package com.keycloak.service;

import com.keycloak.entity.OtpRecord;
import com.keycloak.exceptions.OtpException;
import com.keycloak.repository.OtpRepository;
import com.keycloak.utils.OtpGenerator;
import java.time.LocalDateTime;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository otpRepository;
    private final OtpGenerator otpGenerator;

    @Value("${otp.expiry-minutes:5}")
    private int otpExpiryMinutes;

    @Value("${otp.length:6}")
    private int otpLength;

    @Value("${otp.max-attempts:3}")
    private int maxAttempts;

    @Transactional
    public String generateOtp(String username) {
        log.info("Generating OTP for username: {}", username);

        // Invalidate any existing active OTPs for this user
        invalidateExistingOtps(username);

        // Generate new OTP
        String otpCode = otpGenerator.generateNumericOtp(otpLength);
        LocalDateTime validUntil = LocalDateTime.now().plusMinutes(otpExpiryMinutes);

        OtpRecord otpRecord = OtpRecord.builder()
                .username(username)
                .otpCode(otpCode)
                .validUntil(validUntil)
                .used(false)
                .attempts(0)
                .build();

        otpRepository.save(otpRecord);
        log.info("OTP generated successfully for username: {}, valid until: {}", username, validUntil);

        // In production, send this OTP via email/SMS instead of returning it
        return otpCode;
    }

    @Transactional
    public boolean verifyOtp(String username, String otpCode) {
        log.info("Verifying OTP for username: {}", username);

        Optional<OtpRecord> otpRecordOpt = otpRepository.findByUsernameAndOtpCodeAndUsedFalseAndValidUntilAfter(
                username, otpCode, LocalDateTime.now());

        if (otpRecordOpt.isEmpty()) {
            log.warn("Invalid or expired OTP for username: {}", username);

            // Increment attempts for the latest OTP
            incrementOtpAttempts(username);
            throw new OtpException("Invalid or expired OTP");
        }

        OtpRecord otpRecord = otpRecordOpt.get();

        if (otpRecord.getAttempts() >= maxAttempts) {
            log.warn("Maximum OTP attempts exceeded for username: {}", username);
            throw new OtpException("Maximum OTP attempts exceeded");
        }

        if (!otpRecord.isValid()) {
            log.warn("OTP is not valid for username: {}", username);
            throw new OtpException("OTP is not valid");
        }

        // Mark OTP as used
        otpRecord.setUsed(true);
        otpRecord.setUsedAt(LocalDateTime.now());
        otpRepository.save(otpRecord);

        log.info("OTP verified successfully for username: {}", username);
        return true;
    }

    @Transactional
    public void invalidateExistingOtps(String username) {
        var activeOtps = otpRepository.findByUsernameAndUsedFalseAndValidUntilAfter(username, LocalDateTime.now());

        activeOtps.forEach(otp -> {
            otp.setUsed(true);
            otp.setUsedAt(LocalDateTime.now());
        });

        if (!activeOtps.isEmpty()) {
            otpRepository.saveAll(activeOtps);
            log.info("Invalidated {} existing OTPs for username: {}", activeOtps.size(), username);
        }
    }

    @Transactional
    public void incrementOtpAttempts(String username) {
        Optional<OtpRecord> latestOtpOpt =
                otpRepository.findFirstByUsernameAndUsedFalseAndValidUntilAfterOrderByCreatedAtDesc(
                        username, LocalDateTime.now());

        latestOtpOpt.ifPresent(otpRecord -> {
            otpRecord.setAttempts(otpRecord.getAttempts() + 1);
            otpRepository.save(otpRecord);
            log.info("Incremented OTP attempts for username: {} to {}", username, otpRecord.getAttempts());
        });
    }

    @Transactional
    public void cleanupExpiredOtps() {
        log.info("Cleaning up expired OTPs");
        otpRepository.deleteByValidUntilBefore(LocalDateTime.now());
    }
}
