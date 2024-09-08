package baykov.daniel.cookie_auth.service;

import baykov.daniel.cookie_auth.entity.Token;
import baykov.daniel.cookie_auth.entity.TokenType;
import baykov.daniel.cookie_auth.entity.User;
import baykov.daniel.cookie_auth.model.base.StatusMessageException;
import baykov.daniel.cookie_auth.repository.TokenRepository;
import baykov.daniel.cookie_auth.repository.TokenTypeRepository;
import baykov.daniel.cookie_auth.service.util.ServiceUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

import static baykov.daniel.cookie_auth.constant.ErrorMessages.EMAIL_ALREADY_CONFIRMED;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.EMAIL_ALREADY_CONFIRMED_ERR;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.INVALID_TOKEN_TYPE;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.INVALID_TOKEN_TYPE_ERR;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.RESOURCE_NOT_FOUND_ERR;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.TOKEN_EXPIRED;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.TOKEN_EXPIRED_ERR;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final TokenRepository tokenRepository;
    private final TokenTypeRepository tokenTypeRepository;
    private final ServiceUtil serviceUtil;

    @Transactional
    public void validateToken(String token, TokenType.TokenTypeEnum tokenTypeName) {
        log.info("Validating confirmation token for token type: {}", tokenTypeName);
        Token foundToken = tokenRepository.findByTokenId(token)
                .orElseThrow(() -> StatusMessageException.error(RESOURCE_NOT_FOUND_ERR, token + " does not exist."));

        if (foundToken.getConfirmedAt() != null) {
            log.warn("Token validation failed for token type: {}. Email already confirmed.", tokenTypeName);
            throw StatusMessageException.error(EMAIL_ALREADY_CONFIRMED_ERR, EMAIL_ALREADY_CONFIRMED);
        }

        if (foundToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("Token validation failed for token type: {}. Token has expired.", tokenTypeName);
            throw StatusMessageException.error(TOKEN_EXPIRED_ERR, TOKEN_EXPIRED);
        }

        if (!foundToken.getTokenType().getName().name().equalsIgnoreCase(tokenTypeName.name())) {
            log.warn("Token validation failed for token type: {}. Invalid token type.", tokenTypeName.name());
            throw StatusMessageException.error(INVALID_TOKEN_TYPE_ERR, INVALID_TOKEN_TYPE);
        }

        foundToken.setConfirmedAt(LocalDateTime.now());
        tokenRepository.save(foundToken);
        log.info("Token validation successful for token type: {}", tokenTypeName);
    }

    public void checkForPendingTokens(User user, TokenType.TokenTypeEnum tokenTypeName) {
        log.info("Checking for pending tokens for user: {} with token type: {}", user.getEmail(), tokenTypeName);
        TokenType foundToken = tokenTypeRepository.findTokenTypeByName(tokenTypeName)
                .orElseThrow(() -> StatusMessageException.error(RESOURCE_NOT_FOUND_ERR, tokenTypeName.name() + " does not exist"));

        String lastToken = tokenRepository.findLatestTokenByUserIdAndTokenTypeId(user.getId(), foundToken.getId());
        if (lastToken != null) {
            serviceUtil.checkTokenExpired(lastToken);
            log.info("Checked for pending tokens for user: {} with token type: {}. Result: Token expired or not found.", user.getEmail(), tokenTypeName);
        } else {
            log.info("Checked for pending tokens for user: {} with token type: {}. Result: No pending tokens found.", user.getEmail(), tokenTypeName);
        }
    }
}
