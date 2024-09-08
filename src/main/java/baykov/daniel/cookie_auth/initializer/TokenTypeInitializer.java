package baykov.daniel.cookie_auth.initializer;

import baykov.daniel.cookie_auth.entity.TokenType;
import baykov.daniel.cookie_auth.repository.TokenTypeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class TokenTypeInitializer {

    private final TokenTypeRepository tokenTypeRepository;

    @EventListener
    @Transactional
    public void onApplicationReady(ApplicationReadyEvent event) {
        for (TokenType.TokenTypeEnum tokenTypeEnum : TokenType.TokenTypeEnum.values()) {
            if (!tokenTypeRepository.existsByName(tokenTypeEnum)) {
                TokenType tokenType = new TokenType();
                tokenType.setName(tokenTypeEnum);
                tokenTypeRepository.save(tokenType);
            }
        }
    }
}
