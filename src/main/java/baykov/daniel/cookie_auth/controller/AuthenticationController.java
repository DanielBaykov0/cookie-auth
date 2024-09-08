package baykov.daniel.cookie_auth.controller;


import baykov.daniel.cookie_auth.model.base.StatusMessage;
import baykov.daniel.cookie_auth.model.request.ChangePasswordDTO;
import baykov.daniel.cookie_auth.model.request.ForgotPasswordDTO;
import baykov.daniel.cookie_auth.model.request.LoginDTO;
import baykov.daniel.cookie_auth.model.request.RegisterDTO;
import baykov.daniel.cookie_auth.model.request.VerificationRequestDTO;
import baykov.daniel.cookie_auth.security.util.JWTTokenProvider;
import baykov.daniel.cookie_auth.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final JWTTokenProvider jwtTokenProvider;
    
    @PostMapping(value = "/register")
    public ResponseEntity<StatusMessage> register(@Valid @RequestBody RegisterDTO registerDTO) {
        log.info("Correlation ID: {}. Received request to register a new user.", "correlationId");

        StatusMessage response = authenticationService.register(registerDTO);

        log.info("Correlation ID: {}. User registration completed successfully.", "correlationId");
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    
    @PostMapping(value = "/login")
    public ResponseEntity<StatusMessage> login(@Valid @RequestBody LoginDTO loginDTO,  HttpServletResponse response) {
        log.info("Correlation ID: {}. Received login request for user: {}.", "correlationId", loginDTO.getEmail());

        StatusMessage statusMessage = authenticationService.login(loginDTO, response);

        log.info("Correlation ID: {}. User login successful for user: {}.", "correlationId", loginDTO.getEmail());
        return ResponseEntity.ok(statusMessage);
    }

    
    @PostMapping("/verify-code")
    public ResponseEntity<Boolean> verifyCode(
            @Valid @RequestBody VerificationRequestDTO verificationRequestDTO, Authentication authentication) {
        log.info("Correlation ID: {}. Received verification request for user: {}.", "correlationId", authentication.getName());

        boolean verificationSuccessful = authenticationService.verifyCode(verificationRequestDTO, authentication);
        log.info("Correlation ID: {}. Verification successful for user: {}.", "correlationId", authentication.getName());
        return ResponseEntity.ok(verificationSuccessful);
    }

    
    @PreAuthorize("hasAnyRole('ADMIN', 'LIBRARIAN', 'USER')")
    @GetMapping("/me")
    public ResponseEntity<String> currentUser(Authentication authentication) {
        log.info("Correlation ID: {}. Retrieving current user for authentication: {}.", "correlationId", authentication);

        String currentUserName = authentication.getName();
        log.info("Correlation ID: {}. Current user retrieved: {}.", "correlationId", currentUserName);

        return ResponseEntity.ok(currentUserName);
    }

//    @PreAuthorize("hasAnyRole('ADMIN', 'LIBRARIAN', 'USER')")
//    @GetMapping("/me")
//    public ResponseEntity<String> currentUserCookie(HttpServletRequest request) {
//        Optional<Cookie> optionalCookie = jwtTokenProvider.extractCookie(request, TokenType.TokenTypeEnum.ACCESS.getValue());
//        if (optionalCookie.isPresent()) {
//            Cookie cookie = optionalCookie.get();
//            String currentUserName = cookie.getName();
//        }
//        log.info("Correlation ID: {}. Current user retrieved: {}.", "correlationId", currentUserName);
//
//        return ResponseEntity.ok(currentUserName);
//    }

    
    @PreAuthorize("hasAnyRole('ADMIN', 'LIBRARIAN', 'USER')")
    @PostMapping("/logout")
    public ResponseEntity<StatusMessage> logout(HttpServletRequest request, HttpServletResponse response) {
        log.info("Correlation ID: {}. Logging out user.", "correlationId");

        StatusMessage statusMessage = authenticationService.logout(request, response);

        log.info("Correlation ID: {}. User logged out successfully.", "correlationId");
        return ResponseEntity.ok(statusMessage);
    }

    
//    @PreAuthorize("hasAnyRole('ADMIN', 'LIBRARIAN', 'USER')")
//    @PostMapping("/refresh-token")
//    public ResponseEntity<JwtRefreshResponseDTO> refreshToken(@Valid @RequestBody JwtRefreshRequestDTO refreshRequestDTO) {
//        log.info("Correlation ID: {}. Refreshing token for user...", "correlationId");
//
//        JwtRefreshResponseDTO responseDTO = authenticationService.refreshToken(refreshRequestDTO);
//
//        log.info("Correlation ID: {}. Token refreshed for user.", "correlationId");
//        return ResponseEntity.ok(responseDTO);
//    }

    
    @PreAuthorize("hasAnyRole('ADMIN', 'LIBRARIAN', 'USER')")
    @PatchMapping("/change-password")
    public ResponseEntity<StatusMessage> changePassword(
            @Valid @RequestBody ChangePasswordDTO changePasswordDTO,
            @RequestParam String token) {
        log.info("Change password request received. Correlation ID: {}", "correlationId");

        StatusMessage response = authenticationService.changePassword(changePasswordDTO, token);

        log.info("Change password request completed. Correlation ID: {}", "correlationId");
        return ResponseEntity.ok(response);
    }

    
    @PostMapping("/forgot")
    public ResponseEntity<StatusMessage> forgotPassword(@Valid @RequestBody ForgotPasswordDTO forgotPasswordDTO) {
        log.info("Forgot password request received. Correlation ID: {}", "correlationId");

        StatusMessage response = authenticationService.forgotPassword(forgotPasswordDTO);

        log.info("Forgot password request completed. Correlation ID: {}", "correlationId");
        return ResponseEntity.ok(response);
    }

   
    @PostMapping("/resend-forgot")
    public ResponseEntity<StatusMessage> resendForgotPassword(@RequestParam String token) {
        log.info("Resend forgot password request received. Correlation ID: {}", "correlationId");

        StatusMessage response = authenticationService.resendForgotPassword(token);

        log.info("Resend forgot password request completed. Correlation ID: {}", "correlationId");
        return ResponseEntity.ok(response);
    }
    
    @PreAuthorize("hasAnyRole('ADMIN', 'LIBRARIAN', 'USER')")
    @PostMapping("/send-email-verification")
    public ResponseEntity<StatusMessage> sendEmailVerification(Authentication authentication) {
        log.info("Sending email verification request received. Correlation ID: {}", "correlationId");

        StatusMessage response = authenticationService.sendEmailVerification(authentication.getName());

        log.info("Sending email verification request completed. Correlation ID: {}", "correlationId");
        return ResponseEntity.ok(response);
    }

    
    @GetMapping("/verify-email")
    public ResponseEntity<StatusMessage> verifyEmail(@RequestParam String token) {
        log.info("Verification email request received. Correlation ID: {}", "correlationId");

        StatusMessage response = authenticationService.verifyEmail(token);

        log.info("Verification email completed. Correlation ID: {}", "correlationId");
        return ResponseEntity.ok(response);
    }
}
