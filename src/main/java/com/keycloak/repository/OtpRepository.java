package com.keycloak.repository;

import com.keycloak.entity.OtpRecord;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OtpRepository extends JpaRepository<OtpRecord, Long> {

    Optional<OtpRecord> findByUsernameAndOtpCodeAndUsedFalseAndValidUntilAfter(
            String username, String otpCode, LocalDateTime currentTime);

    List<OtpRecord> findByUsernameAndUsedFalseAndValidUntilAfter(String username, LocalDateTime currentTime);

    Optional<OtpRecord> findFirstByUsernameAndUsedFalseAndValidUntilAfterOrderByCreatedAtDesc(
            String username, LocalDateTime currentTime);

    void deleteByValidUntilBefore(LocalDateTime time);
}
