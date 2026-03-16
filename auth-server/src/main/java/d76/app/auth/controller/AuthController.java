package d76.app.auth.controller;

import d76.app.auth.dto.request.*;
import d76.app.auth.dto.response.RegisterResponse;
import d76.app.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@NullMarked
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.ACCEPTED)
    void register(@RequestBody @Valid RegisterRequest request) {
        authService.register(request);
    }

    @PostMapping("/register/complete")
    ResponseEntity<RegisterResponse> completeRegistration(
            @RequestBody @Valid OtpVerifyRequest request) {
        var response = authService.completeRegistration(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/otp/resend")
    @ResponseStatus(HttpStatus.ACCEPTED)
    void resendOtp(@RequestBody @Valid OtpRequest request) {
        authService.resendOtp(request);
    }

    @PostMapping("/password/forgot")
    @ResponseStatus(HttpStatus.ACCEPTED)
    void forgotPassword(@RequestBody @Valid ForgotPasswordRequest request) {
        authService.forgotPassword(request.email());
    }

    @PostMapping("/password/reset")
    @ResponseStatus(HttpStatus.OK)
    void resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        authService.resetPassword(request);
    }
}