package d76.app.auth.service;

import d76.app.auth.dto.TempUser;
import d76.app.auth.dto.request.*;
import d76.app.auth.dto.response.RegisterResponse;
import d76.app.auth.exception.AuthErrorCode;
import d76.app.auth.model.IdentityProvider;
import d76.app.core.service.CacheService;
import d76.app.notification.email.service.MailService;
import d76.app.notification.otp.model.OtpPurpose;
import d76.app.notification.otp.service.OtpService;
import d76.app.user.service.UserService;
import dev.d76.spring.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final String TEMP_REGISTER_PREFIX = "register:temp:";

    @Value("${application.registration.ttl.seconds}")
    private Long registrationTTL;

    private final UserService userService;
    private final OtpService otpService;
    private final MailService mailService;
    private final CacheService cacheService;

    @Transactional
    public void register(RegisterRequest request) {
        userService.assertUsernameAvailable(request.userName());
        userService.assertEmailAvailable(request.email());

        cacheService.put(
                tempRegisterKey(request.email()),
                new TempUser(request.email(), request.userName(), request.password()),
                registrationTTL,
                TimeUnit.SECONDS
        );

        var purpose = OtpPurpose.EMAIL_VERIFICATION;
        var otp = otpService.issueOtp(request.email(), purpose);
        mailService.sendTextMail(request.email(), purpose.subject(), purpose.body(otp));
    }

    @Transactional
    public RegisterResponse completeRegistration(OtpVerifyRequest request) {
        otpService.verifyOtp(request.email(), request.otp(), OtpPurpose.EMAIL_VERIFICATION);

        var tempUser = cacheService
                .get(tempRegisterKey(request.email()), TempUser.class)
                .orElseThrow(() -> new BusinessException(AuthErrorCode.REGISTER_SESSION_EXPIRED));

        cacheService.evict(tempRegisterKey(request.email()));

        var user = userService.createLocalUser(
                tempUser.email(), tempUser.username(), tempUser.password());

        return new RegisterResponse(user.getEmail(), IdentityProvider.EMAIL.name(), Instant.now());
    }

    public void resendOtp(OtpRequest request) {
        if (OtpPurpose.EMAIL_VERIFICATION.equals(request.purpose())) {
            userService.assertEmailAvailable(request.email());
        }

        var otp = otpService.issueOtp(request.email(), request.purpose());
        mailService.sendTextMail(request.email(), request.purpose().subject(), request.purpose().body(otp));
    }

    public void forgotPassword(String email) {
        userService.assertUserExistByEmail(email);

        var purpose = OtpPurpose.PASSWORD_RESET;
        var otp = otpService.issueOtp(email, purpose);
        mailService.sendTextMail(email, purpose.subject(), purpose.body(otp));
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        otpService.verifyOtp(request.email(), request.otp(), OtpPurpose.PASSWORD_RESET);
        userService.updatePassword(request.email(), request.newPassword());
    }

    private String tempRegisterKey(String email) {
        return TEMP_REGISTER_PREFIX + email;
    }
}