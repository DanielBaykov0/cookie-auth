package baykov.daniel.cookie_auth.repository;

import baykov.daniel.cookie_auth.entity.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenTypeRepository extends JpaRepository<TokenType, Long> {

    Optional<TokenType> findTokenTypeByName(TokenType.TokenTypeEnum tokenTypeName);

    boolean existsByName(TokenType.TokenTypeEnum name);
}
