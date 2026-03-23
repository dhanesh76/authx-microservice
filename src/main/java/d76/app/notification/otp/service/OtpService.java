package d76.app.notification.otp.service;

import d76.app.core.service.CacheService;
import d76.app.notification.otp.exception.OtpErrorCode;
import d76.app.notification.otp.model.OtpData;
import d76.app.notification.otp.model.OtpPurpose;
import dev.d76.spring.exception.BusinessException;
import jakarta.transaction.Transactional;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class OtpService {

    private final CacheService cacheService;
    private final SecureRandom secureRandom;
    private final int otpLength;

    @Getter
    private final long ttlSeconds;

    public OtpService(
            CacheService cacheService,
            @Value("${application.otp.length}") int otpLength,
            @Value("${application.otp.ttl.seconds}") long ttlSeconds
    ) {
        this.cacheService = cacheService;
        this.otpLength = otpLength;
        this.ttlSeconds = ttlSeconds;
        this.secureRandom = new SecureRandom();
    }

    @Transactional
    public String issueOtp(String email, OtpPurpose purpose) {
        String otp = generateOtp();
        cacheService.put(otpKey(email, purpose), new OtpData(otp, purpose, Instant.now()), ttlSeconds, TimeUnit.SECONDS);
        return otp;
    }

    @Transactional
    public void verifyOtp(String email, String otp, OtpPurpose purpose) {
        String key = otpKey(email, purpose);

        OtpData otpData = cacheService.get(key, OtpData.class)
                .orElseThrow(() -> new BusinessException(OtpErrorCode.OTP_EXPIRED));

        if (!purpose.equals(otpData.purpose())) {
            log.warn("OTP purpose mismatch email={} expected={} actual={}",
                    email, purpose, otpData.purpose());
            throw new BusinessException(OtpErrorCode.INVALID_OTP);
        }

        if (!otp.equals(otpData.otp())) {
            log.warn("OTP value mismatch email={} purpose={}", email, purpose);
            throw new BusinessException(OtpErrorCode.INVALID_OTP);
        }

        cacheService.evict(key);
    }

    private String otpKey(String email, OtpPurpose purpose) {
        return email + ":" + purpose.name();
    }

    private String generateOtp() {
        int range = (int) Math.pow(10, otpLength);
        return String.format("%0" + otpLength + "d", secureRandom.nextInt(range));
    }
}