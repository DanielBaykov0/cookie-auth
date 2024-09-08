package baykov.daniel.cookie_auth.service.util;

import baykov.daniel.cookie_auth.entity.Role;
import baykov.daniel.cookie_auth.entity.Token;
import baykov.daniel.cookie_auth.model.base.StatusMessageException;
import baykov.daniel.cookie_auth.repository.RoleRepository;
import baykov.daniel.cookie_auth.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static baykov.daniel.cookie_auth.constant.ErrorMessages.PREVIOUS_TOKEN_NOT_EXPIRED;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.PREVIOUS_TOKEN_NOT_EXPIRED_ERR;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.TOKEN_MISSING_ERR;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.TOKEN_NOT_FOUND;

@Slf4j
@Component
@RequiredArgsConstructor
public class ServiceUtil {

    private final RoleRepository roleRepository;
    private final TokenRepository tokenRepository;

    public Set<Role> setRoles() {
        Set<Role> roles = new HashSet<>();
        Optional<Role> userRole = roleRepository.findByName(Role.RoleEnum.ROLE_USER);
        Role role = new Role();
        if (userRole.isPresent()) {
            role = userRole.get();
        }
        roles.add(role);
        return roles;
    }

    public void checkTokenExpired(String token) {
        log.info("Checking if token is expired.");
        Token foundToken = tokenRepository.findByTokenId(token)
                .orElseThrow(() -> {
                    log.error("Token not found: {}", token);
                    return StatusMessageException.error(HttpStatus.NOT_FOUND.value(), TOKEN_MISSING_ERR, TOKEN_NOT_FOUND);
                });

        if (foundToken.getExpiresAt().isAfter(LocalDateTime.now())) {
            log.error("Token is not expired: {}", token);
            throw StatusMessageException.error(PREVIOUS_TOKEN_NOT_EXPIRED_ERR, PREVIOUS_TOKEN_NOT_EXPIRED);
        }

        log.info("Token check for expiration completed.");
    }

    public void checkTokenValid(String token) {
        log.info("Checking if token is valid.");
        Token foundToken = tokenRepository.findByTokenId(token)
                .orElseThrow(() -> {
                    log.error("Token not found: {}", token);
                    return StatusMessageException.error(HttpStatus.NOT_FOUND.value(), TOKEN_MISSING_ERR, TOKEN_NOT_FOUND);
                });

        if (foundToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.error("Token is expired: {}", token);
            throw StatusMessageException.error(PREVIOUS_TOKEN_NOT_EXPIRED_ERR, PREVIOUS_TOKEN_NOT_EXPIRED);
        }

        log.info("Token check for validity completed.");
    }
}
