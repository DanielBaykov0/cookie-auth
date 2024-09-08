package baykov.daniel.cookie_auth.service;

import baykov.daniel.cookie_auth.entity.Token;
import baykov.daniel.cookie_auth.entity.TokenType;
import baykov.daniel.cookie_auth.entity.User;
import baykov.daniel.cookie_auth.model.base.StatusMessageException;
import baykov.daniel.cookie_auth.repository.TokenRepository;
import baykov.daniel.cookie_auth.repository.TokenTypeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import static baykov.daniel.cookie_auth.constant.ErrorMessages.RESOURCE_NOT_FOUND_ERR;

@Component
@RequiredArgsConstructor
public class TokenTypeService {

    private final TokenTypeRepository tokenTypeRepository;
    private final TokenRepository tokenRepository;

    @Transactional
    public String createNewToken(User user, TokenType.TokenTypeEnum tokenTypeName) {
        TokenType tokenType = tokenTypeRepository.findTokenTypeByName(tokenTypeName)
                .orElseThrow(() -> StatusMessageException.error(RESOURCE_NOT_FOUND_ERR, tokenTypeName.name() + " does not exist."));

        Token token = new Token(user, tokenType);
        tokenRepository.save(token);
        return token.getTokenId();
    }
}
