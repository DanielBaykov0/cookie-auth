package baykov.daniel.cookie_auth.service;

import baykov.daniel.cookie_auth.entity.TokenType;
import baykov.daniel.cookie_auth.entity.User;
import baykov.daniel.cookie_auth.model.base.StatusMessage;
import baykov.daniel.cookie_auth.model.base.StatusMessageException;
import baykov.daniel.cookie_auth.model.request.ChangePasswordDTO;
import baykov.daniel.cookie_auth.model.request.ForgotPasswordDTO;
import baykov.daniel.cookie_auth.model.request.LoginDTO;
import baykov.daniel.cookie_auth.model.request.RegisterDTO;
import baykov.daniel.cookie_auth.model.request.VerificationRequestDTO;
import baykov.daniel.cookie_auth.repository.TokenRepository;
import baykov.daniel.cookie_auth.repository.UserRepository;
import baykov.daniel.cookie_auth.security.util.JWTTokenProvider;
import baykov.daniel.cookie_auth.service.util.ServiceUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static baykov.daniel.cookie_auth.constant.ErrorMessages.EMAIL_ALREADY_EXISTS;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.EMAIL_ALREADY_VERIFIED_ERR;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.EMAIL_EXISTS_ERR;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.EMAIL_NOT_VERIFIED;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.EMAIL_NOT_VERIFIED_ERR;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.RESOURCE_NOT_FOUND_ERR;
import static baykov.daniel.cookie_auth.constant.Messages.EMAIL_ALREADY_VERIFIED;

@Slf4j
@Service
@AllArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final ServiceUtil serviceUtil;
    private final UserRepository userRepository;
    private final TokenTypeService tokenTypeService;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTTokenProvider jwtTokenProvider;
    private final TokenService tokenService;
//    private final EmailBuilderService emailBuilderService;
//    private final EmailService emailService;
//    private final MFAService mfaService;
//    private final PropertyVariables propertyVariables;

    @Transactional
    public StatusMessage register(RegisterDTO registerDTO) {
        log.info("Received request to register a new user with email: {}", registerDTO.getEmail());
        if (userRepository.existsByEmailIgnoreCase(registerDTO.getEmail())) {
            log.error("Registration failed. Email '{}' already exists.", registerDTO.getEmail());
            throw StatusMessageException.error(EMAIL_EXISTS_ERR, EMAIL_ALREADY_EXISTS);
        }

        User user = User.builder()
                .fullName(registerDTO.getFullName())
                .email(registerDTO.getEmail())
                .password(passwordEncoder.encode(registerDTO.getPassword()))
                .isAccountNonExpired(true)
                .isAccountNonLocked(true)
                .isCredentialsNonExpired(true)
                .isEnabled(false)
                .roles(serviceUtil.setRoles())
                .build();

        userRepository.save(user);

        String token = tokenTypeService.createNewToken(user, TokenType.TokenTypeEnum.VERIFICATION);
        log.info("User token: {}", token);

        log.info("User registered successfully with email: {}", registerDTO.getEmail());
        return StatusMessage.success();
    }

    public StatusMessage login(LoginDTO loginDTO, HttpServletResponse response) {
        log.info("Received login request for user with email: {}", loginDTO.getEmail());

        User user = userRepository.findByEmailIgnoreCase(loginDTO.getEmail())
                .orElseThrow(() -> StatusMessageException.error(RESOURCE_NOT_FOUND_ERR, loginDTO.getEmail() + " does not exist"));

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                loginDTO.getEmail(),
                                loginDTO.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        jwtTokenProvider.addCookie(response, authentication, TokenType.TokenTypeEnum.ACCESS);
        userRepository.save(user);

        log.info("User logged in successfully without MFA secret: {}", loginDTO.getEmail());
        return StatusMessage.success();
    }

    public StatusMessage logout(HttpServletRequest request, HttpServletResponse response) {
        jwtTokenProvider.removeCookie(request, response, TokenType.TokenTypeEnum.ACCESS.getValue());
        SecurityContextHolder.clearContext();
        log.info("User logged out successfully.");
        return StatusMessage.success();
    }

//    public JwtRefreshResponseDTO refreshToken(JwtRefreshRequestDTO refreshRequestDTO) {
//        String requestRefreshToken = refreshRequestDTO.getRefreshToken();
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//
//        if (authentication == null) {
//            throw new LibraryHTTPException(HttpStatus.UNAUTHORIZED, NOT_AUTHENTICATED);
//        }
//
//        if (!jwtTokenProvider.validateToken(requestRefreshToken)) {
//            throw new LibraryHTTPException(HttpStatus.BAD_REQUEST, REFRESH_TOKEN_EXPIRED);
//        }
//
//        String accessToken = jwtTokenProvider.generateAccessToken(authentication);
//        String refreshToken = jwtTokenProvider.generateRefreshToken(authentication);
//        log.info("Refreshed access token successfully.");
//        return new JwtRefreshResponseDTO(accessToken, refreshToken);
//    }

    @Transactional
    public StatusMessage changePassword(ChangePasswordDTO changePasswordDTO, String token) {
        Long userId = tokenRepository.findUserIdByTokenId(token);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> StatusMessageException.error(RESOURCE_NOT_FOUND_ERR, userId + " does not exist"));

        tokenService.validateToken(token, TokenType.TokenTypeEnum.RESET);

        user.setPassword(passwordEncoder.encode(changePasswordDTO.getPassword()));
        userRepository.save(user);

        log.info("Password changed successfully for user with id: {}", userId);
        return StatusMessage.success();
    }

    @Transactional
    public StatusMessage forgotPassword(ForgotPasswordDTO forgotPasswordDTO) {
        User user = userRepository
                .findByEmailIgnoreCase(forgotPasswordDTO.getEmail())
                .orElseThrow(() -> StatusMessageException.error(RESOURCE_NOT_FOUND_ERR, forgotPasswordDTO.getEmail() + " does not exist"));

        if (!user.isEmailVerified()) {
            log.error("Forgot Password failed for user with unverified email: {}", forgotPasswordDTO.getEmail());
            throw StatusMessageException.error(HttpStatus.FORBIDDEN.value(), EMAIL_NOT_VERIFIED_ERR, EMAIL_NOT_VERIFIED);
        }

        tokenService.checkForPendingTokens(user, TokenType.TokenTypeEnum.RESET);

        String token = tokenTypeService.createNewToken(user, TokenType.TokenTypeEnum.RESET);
        serviceUtil.checkTokenValid(token);

        log.info("Forgot Password email sent to user with email: {}", user.getEmail());
        return StatusMessage.success();
    }

    @Transactional
    public StatusMessage resendForgotPassword(String token) {
        Long userId = tokenRepository.findUserIdByTokenId(token);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> StatusMessageException.error(RESOURCE_NOT_FOUND_ERR, userId + " does not exist"));

        tokenService.checkForPendingTokens(user, TokenType.TokenTypeEnum.RESET);

        String newToken = tokenTypeService.createNewToken(user, TokenType.TokenTypeEnum.RESET);
        serviceUtil.checkTokenValid(newToken);

        log.info("Resent Forgot Password email to user with email: {}", user.getEmail());
        return StatusMessage.success();
    }

    @Transactional
    public StatusMessage sendEmailVerification(String email) {
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> StatusMessageException.error(RESOURCE_NOT_FOUND_ERR, email + " does not exist"));

        if (user.isEmailVerified()) {
            log.error("Email Verification failed for user with already verified email: {}", email);
            throw StatusMessageException.error(EMAIL_ALREADY_VERIFIED_ERR, EMAIL_ALREADY_VERIFIED);
        }

        tokenService.checkForPendingTokens(user, TokenType.TokenTypeEnum.VERIFICATION);

        String newToken = tokenTypeService.createNewToken(user, TokenType.TokenTypeEnum.VERIFICATION);
        serviceUtil.checkTokenValid(newToken);

//        emailService.send("Email Confirmation", user.getEmail(),
//                emailBuilderService.buildConfirmationEmail(
//                        user.getFirstName(),
//                        user.getLastName(),
//                        propertyVariables.getConfirmEmailUri() + newToken));


        log.info("Sent Email Verification email to user with email: {}", user.getEmail());
        return StatusMessage.success();
    }

    @Transactional
    public StatusMessage verifyEmail(String token) {
        log.info("Verifying email with token: {}", token);
        tokenService.validateToken(token, TokenType.TokenTypeEnum.VERIFICATION);

        Long userId = tokenRepository.findUserIdByTokenId(token);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> StatusMessageException.error(RESOURCE_NOT_FOUND_ERR, userId + " does not exist"));

        user.setEmailVerified(true);
        userRepository.save(user);

        log.info("Email verified successfully for user with email: {}", user.getEmail());
        return StatusMessage.success();
    }

    public boolean verifyCode(VerificationRequestDTO verificationRequestDTO, Authentication authentication) {
        User user = userRepository.findByEmailIgnoreCase(authentication.getName())
                .orElseThrow(() -> StatusMessageException.error(RESOURCE_NOT_FOUND_ERR, authentication.getName() + " does not exist"));

//        if (mfaService.isOtpNotValid(user.getSecret(), verificationRequestDTO.getCode())) {
//            throw new LibraryHTTPException(HttpStatus.BAD_REQUEST, VERIFICATION_CODE_NOT_CORRECT);
//        }

        log.info("Verification code verified successfully for user with email: {}", authentication.getName());
        return true;
    }
}
