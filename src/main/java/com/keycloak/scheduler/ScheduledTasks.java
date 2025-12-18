package com.keycloak.scheduler;

import com.keycloak.service.OtpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Slf4j
@Configuration
@EnableScheduling
@RequiredArgsConstructor
public class ScheduledTasks {

    private final OtpService otpService;

    /**
     * Cleanup expired OTPs every hour
     */
    @Scheduled(cron = "0 0 * * * *")
    public void cleanupExpiredOtps() {
        log.info("Running scheduled task: Cleanup expired OTPs");
        otpService.cleanupExpiredOtps();
    }
}
